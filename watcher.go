package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type fileState struct {
	hash    string
	size    int64
	content []byte // nil if binary or beyond maxContent
	binary  bool
}

type Watcher struct {
	cfg        *Config
	log        *Logger
	fs         *fsnotify.Watcher
	mu         sync.Mutex
	state      map[string]fileState
	debounce   map[string]*time.Timer
	editors    map[string]ProcessInfo // latest candidate per path, cleared in process()
	maxHash    int64
	maxContent int64
	maxDiffOut int
}

func NewWatcher(cfg *Config, lg *Logger) (*Watcher, error) {
	fs, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		cfg:        cfg,
		log:        lg,
		fs:         fs,
		state:      map[string]fileState{},
		debounce:   map[string]*time.Timer{},
		editors:    map[string]ProcessInfo{},
		maxHash:    cfg.MaxHashSizeMB * 1024 * 1024,
		maxContent: cfg.MaxDiffSizeKB * 1024,
		maxDiffOut: cfg.MaxDiffOutputKB * 1024,
	}
	for _, p := range cfg.Paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			lg.Log(Event{EventType: "watch_error", Path: p, Error: err.Error()})
			continue
		}
		if err := w.addPath(abs); err != nil {
			lg.Log(Event{EventType: "watch_error", Path: abs, Error: err.Error()})
		}
	}
	return w, nil
}

func (w *Watcher) snapshot(path string) (Snapshot, error) {
	return ReadSnapshot(path, w.maxHash, w.maxContent)
}

func (w *Watcher) addPath(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		if err := w.fs.Add(filepath.Dir(root)); err != nil {
			return err
		}
		if w.cfg.HashFiles {
			s, _ := w.snapshot(root)
			w.state[root] = fileState{hash: s.Hash, size: s.Size, content: s.Content, binary: s.Binary}
		}
		return nil
	}
	if !w.cfg.Recursive {
		return w.fs.Add(root)
	}
	return filepath.Walk(root, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if w.ignored(p) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() {
			return w.fs.Add(p)
		}
		if w.cfg.HashFiles {
			s, _ := w.snapshot(p)
			w.state[p] = fileState{hash: s.Hash, size: s.Size, content: s.Content, binary: s.Binary}
		}
		return nil
	})
}

func (w *Watcher) ignored(path string) bool {
	base := filepath.Base(path)
	for _, pat := range w.cfg.IgnorePatterns {
		if matched, _ := filepath.Match(pat, base); matched {
			return true
		}
		if strings.Contains(path, pat) {
			return true
		}
	}
	return false
}

func (w *Watcher) Run(ctx context.Context) error {
	debounceDur := time.Duration(w.cfg.DebounceMs) * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.fs.Events:
			if !ok {
				return nil
			}
			if w.ignored(ev.Name) {
				continue
			}
			name := ev.Name
			op := ev.Op

			// Scan IMMEDIATELY — by the time the debounce fires the editor
			// may have closed the file. Last writer wins across the burst.
			if w.cfg.DetectEditor != nil && *w.cfg.DetectEditor {
				if procs := ProcessesHoldingFile(name); len(procs) > 0 {
					w.mu.Lock()
					w.editors[name] = procs[0]
					w.mu.Unlock()
				}
			}

			w.mu.Lock()
			if t, ok := w.debounce[name]; ok {
				t.Stop()
			}
			w.debounce[name] = time.AfterFunc(debounceDur, func() {
				w.process(name, op)
			})
			w.mu.Unlock()
		case err, ok := <-w.fs.Errors:
			if !ok {
				return nil
			}
			w.log.Log(Event{EventType: "watcher_error", Error: err.Error()})
		}
	}
}

func (w *Watcher) process(name string, op fsnotify.Op) {
	w.mu.Lock()
	prev, hadPrev := w.state[name]
	delete(w.debounce, name)
	editor, hasEditor := w.editors[name]
	w.mu.Unlock()
	// editors[name] is cleared only after we successfully emit an event for
	// this path — otherwise a locked-file snapshot would lose the editor info
	// before the next debounce cycle.

	switch {
	// Many editors (and our own Write tool) do atomic-replace: write a tmp file
	// then rename it over the original. That produces a Create event for the
	// destination path, not a Write — so Create and Write must share logic.
	case op&(fsnotify.Create|fsnotify.Write) != 0:
		info, err := os.Stat(name)
		if err != nil {
			return
		}
		if info.IsDir() {
			if op&fsnotify.Create != 0 {
				if w.cfg.Recursive {
					_ = w.fs.Add(name)
				}
				user, _ := FileOwner(name)
				w.log.Log(Event{EventType: "dir_created", Path: name, User: user})
				w.mu.Lock()
				delete(w.editors, name)
				w.mu.Unlock()
			}
			return
		}
		snap, err := w.snapshot(name)
		if err != nil {
			// File likely locked by the editor — leave state & editor cache
			// intact so the next event (after editor closes) can attribute it.
			return
		}
		if hadPrev && snap.Hash == prev.hash && snap.Size == prev.size {
			w.mu.Lock()
			delete(w.editors, name)
			w.mu.Unlock()
			return // no-op
		}
		user, _ := FileOwner(name)

		var diffStr string
		var diffTrunc bool
		if w.maxContent > 0 && hadPrev && !prev.binary && !snap.Binary &&
			prev.content != nil && snap.Content != nil {
			diffStr, diffTrunc = UnifiedDiff(prev.content, snap.Content,
				w.cfg.DiffContextLines, w.maxDiffOut)
		}

		w.mu.Lock()
		w.state[name] = fileState{hash: snap.Hash, size: snap.Size, content: snap.Content, binary: snap.Binary}
		w.mu.Unlock()

		eventType := "modified"
		if !hadPrev {
			eventType = "created"
		}
		evt := Event{
			EventType: eventType, Path: name, User: user,
			HashAfter: snap.Hash, SizeAfter: snap.Size,
			Diff: diffStr, DiffTruncated: diffTrunc,
			IsBinary: snap.Binary,
		}
		if hadPrev {
			evt.HashBefore = prev.hash
			evt.SizeBefore = prev.size
		}
		if hasEditor {
			attachEditor(&evt, editor)
		}
		w.log.Log(evt)
		w.mu.Lock()
		delete(w.editors, name)
		w.mu.Unlock()

	case op&fsnotify.Remove != 0:
		w.mu.Lock()
		delete(w.state, name)
		delete(w.editors, name)
		w.mu.Unlock()
		evt := Event{
			EventType: "deleted", Path: name,
			HashBefore: prev.hash, SizeBefore: prev.size,
			IsBinary: prev.binary,
		}
		if hasEditor {
			attachEditor(&evt, editor)
		}
		w.log.Log(evt)

	case op&fsnotify.Rename != 0:
		w.mu.Lock()
		delete(w.state, name)
		delete(w.editors, name)
		w.mu.Unlock()
		evt := Event{
			EventType: "renamed_from", Path: name,
			HashBefore: prev.hash, SizeBefore: prev.size,
		}
		if hasEditor {
			attachEditor(&evt, editor)
		}
		w.log.Log(evt)

	case op&fsnotify.Chmod != 0:
		user, _ := FileOwner(name)
		evt := Event{EventType: "permission_changed", Path: name, User: user}
		if hasEditor {
			attachEditor(&evt, editor)
		}
		w.log.Log(evt)
		w.mu.Lock()
		delete(w.editors, name)
		w.mu.Unlock()
	}
}

func attachEditor(e *Event, p ProcessInfo) {
	e.EditorPID = p.PID
	e.EditorUser = p.User
	e.EditorProc = p.Name
	e.EditorExe = p.Exe
}

func (w *Watcher) Close() error {
	return w.fs.Close()
}
