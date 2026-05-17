//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FanotifyWatcher is the kernel-assisted backend. fanotify(7) delivers each
// FS event together with the PID that triggered it — same identity signal
// auditd uses, but exposed as plain file events rather than syscall records.
//
// Mode: FAN_CLASS_NOTIF + FAN_MARK_FILESYSTEM (or FAN_MARK_MOUNT fallback).
// Event subscribed: FAN_CLOSE_WRITE — fires when any process that opened the
// file for writing finally closes it. This single signal captures both
// in-place edits and atomic-rename tmp writers, without the spam of FAN_MODIFY.
//
// Requires CAP_SYS_ADMIN (effectively root). Pure Linux. No content-delete
// notification in basic (non-FID) mode — use auditd if delete attribution
// matters as much as write attribution.
type FanotifyWatcher struct {
	cfg        *Config
	log        *Logger
	fd         int
	paths      []string // absolute root paths for in-scope filter
	mu         sync.Mutex
	state      map[string]fileState
	debounce   map[string]*fanPending
	maxHash    int64
	maxContent int64
	maxDiffOut int
	debDur     time.Duration
}

type fanPending struct {
	timer *time.Timer
	pid   uint32
}

func NewFanotifyWatcher(cfg *Config, lg *Logger) (*FanotifyWatcher, error) {
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
	)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w (needs CAP_SYS_ADMIN / root)", err)
	}

	w := &FanotifyWatcher{
		cfg:        cfg,
		log:        lg,
		fd:         fd,
		state:      map[string]fileState{},
		debounce:   map[string]*fanPending{},
		maxHash:    cfg.MaxHashSizeMB * 1024 * 1024,
		maxContent: cfg.MaxDiffSizeKB * 1024,
		maxDiffOut: cfg.MaxDiffOutputKB * 1024,
		debDur:     time.Duration(cfg.DebounceMs) * time.Millisecond,
	}

	mask := uint64(unix.FAN_CLOSE_WRITE)
	for _, p := range cfg.Paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		// FILESYSTEM (4.20+) covers the entire fs containing this path; we
		// filter events back down to the user's path set in userspace.
		err = unix.FanotifyMark(fd,
			unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
			mask, unix.AT_FDCWD, abs)
		if err != nil {
			// Older kernels: fall back to mount-mark.
			err = unix.FanotifyMark(fd,
				unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
				mask, unix.AT_FDCWD, abs)
		}
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("fanotify_mark %s: %w", abs, err)
		}
		w.paths = append(w.paths, abs)
	}

	for _, root := range w.paths {
		w.seedPath(root)
	}
	return w, nil
}

func (w *FanotifyWatcher) seedPath(root string) {
	info, err := os.Stat(root)
	if err != nil {
		return
	}
	if !info.IsDir() {
		if w.cfg.HashFiles {
			s, _ := ReadSnapshot(root, w.maxHash, w.maxContent)
			w.state[root] = fileState{hash: s.Hash, size: s.Size, content: s.Content, binary: s.Binary}
		}
		return
	}
	if !w.cfg.Recursive {
		return
	}
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if w.ignored(p) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !fi.IsDir() && w.cfg.HashFiles {
			s, _ := ReadSnapshot(p, w.maxHash, w.maxContent)
			w.state[p] = fileState{hash: s.Hash, size: s.Size, content: s.Content, binary: s.Binary}
		}
		return nil
	})
}

func (w *FanotifyWatcher) ignored(path string) bool {
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

func (w *FanotifyWatcher) inScope(path string) bool {
	for _, p := range w.paths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func (w *FanotifyWatcher) Run(ctx context.Context) error {
	buf := make([]byte, 4096*32)
	pfd := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
	metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// 500ms timeout so ctx cancellation is observed promptly.
		n, err := unix.Poll(pfd, 500)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("poll: %w", err)
		}
		if n == 0 || pfd[0].Revents&unix.POLLIN == 0 {
			continue
		}

		nb, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == unix.EAGAIN {
				continue
			}
			return fmt.Errorf("read fanotify: %w", err)
		}

		off := 0
		for off+metaSize <= nb {
			meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[off]))
			evtLen := int(meta.Event_len)
			if evtLen < metaSize {
				break
			}

			if meta.Fd >= 0 {
				path, lerr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
				if lerr == nil && w.inScope(path) && !w.ignored(path) {
					w.handle(path, meta.Mask, uint32(meta.Pid))
				}
				unix.Close(int(meta.Fd))
			}
			off += evtLen
		}
	}
}

func (w *FanotifyWatcher) handle(path string, mask uint64, pid uint32) {
	_ = mask // currently only FAN_CLOSE_WRITE subscribed
	w.mu.Lock()
	if p, ok := w.debounce[path]; ok {
		p.timer.Stop()
	}
	p := &fanPending{pid: pid}
	p.timer = time.AfterFunc(w.debDur, func() {
		w.process(path, p.pid)
	})
	w.debounce[path] = p
	w.mu.Unlock()
}

func (w *FanotifyWatcher) process(path string, pid uint32) {
	w.mu.Lock()
	prev, hadPrev := w.state[path]
	delete(w.debounce, path)
	w.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		// Disappeared between event and process — most likely deleted.
		// fanotify basic mode doesn't deliver FAN_DELETE; ignore quietly.
		w.mu.Lock()
		delete(w.state, path)
		w.mu.Unlock()
		return
	}
	if info.IsDir() {
		return
	}

	snap, err := ReadSnapshot(path, w.maxHash, w.maxContent)
	if err != nil {
		return
	}
	if hadPrev && snap.Hash == prev.hash && snap.Size == prev.size {
		return
	}

	var diffStr string
	var diffTrunc bool
	if w.maxContent > 0 && hadPrev && !prev.binary && !snap.Binary &&
		prev.content != nil && snap.Content != nil {
		diffStr, diffTrunc = UnifiedDiff(prev.content, snap.Content,
			w.cfg.DiffContextLines, w.maxDiffOut)
	}

	w.mu.Lock()
	w.state[path] = fileState{hash: snap.Hash, size: snap.Size, content: snap.Content, binary: snap.Binary}
	w.mu.Unlock()

	eventType := "modified"
	if !hadPrev {
		eventType = "created"
	}

	fileUser, _ := FileOwner(path)
	// loadProcInfo is defined in proc_linux.go — same /proc reader used by
	// the fsnotify fallback, so we get loginuid (AUID) here too.
	editor := loadProcInfo(int(pid))

	evt := Event{
		EventType: eventType, Path: path, User: fileUser,
		HashAfter: snap.Hash, SizeAfter: snap.Size,
		Diff: diffStr, DiffTruncated: diffTrunc,
		IsBinary: snap.Binary,
	}
	if hadPrev {
		evt.HashBefore = prev.hash
		evt.SizeBefore = prev.size
	}
	editor.PID = int(pid)
	attachEditor(&evt, editor)
	w.log.Log(evt)
}

func (w *FanotifyWatcher) Close() error {
	return unix.Close(w.fd)
}
