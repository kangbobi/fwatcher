//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Kernel constants not yet (or not always) exported by golang.org/x/sys/unix.
// Stable since Linux 5.15 (pidfd) — defined here for portability across
// older x/sys releases.
const (
	fanReportPidfd        = 0x00000080 // fanotify_init flag
	fanEventInfoTypePidfd = 4          // info record type tag
	fanNoPidfd            = int32(-1)  // event delivered but no associated proc
	fanEPidfd             = int32(-2)  // pidfd alloc failed (proc already dead)
)

// FanotifyWatcher is the kernel-assisted backend. fanotify(7) delivers each
// FS event together with the PID that triggered it — same data quality as
// what auditd reports for write syscalls, but routed through the notification
// API instead of the audit subsystem.
//
// Mode: FAN_CLASS_NOTIF + FAN_MARK_FILESYSTEM (fallback FAN_MARK_MOUNT).
// Event subscribed: FAN_CLOSE_WRITE — fires when any process that opened the
// file for writing finally closes it. One signal captures both in-place edits
// and atomic-rename tmp writers, without FAN_MODIFY's per-syscall spam.
//
// When supported (Linux 5.15+), the watcher requests FAN_REPORT_PIDFD so the
// kernel additionally pins the originating process via a pidfd. That removes
// the PID-reuse race the /proc fallback can hit when the writer exits between
// event delivery and our /proc lookup.
//
// Requires CAP_SYS_ADMIN (effectively root). Pure Linux. No content-delete
// notification in basic (non-FID) mode — use auditd if delete attribution
// matters as much as write attribution.
type FanotifyWatcher struct {
	cfg        *Config
	log        *Logger
	fd         int
	hasPidfd   bool // FAN_REPORT_PIDFD active for this fd
	paths      []string
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
	pidfd int // -1 when unavailable; owned by this struct until close
}

func NewFanotifyWatcher(cfg *Config, lg *Logger) (*FanotifyWatcher, error) {
	eventFlags := uint(unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC)

	// Prefer kernel 5.15+ behaviour where each event carries a pidfd that
	// holds the originating task's PID slot until we close it. Fall back to
	// the basic mode on older kernels.
	hasPidfd := true
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|fanReportPidfd,
		eventFlags,
	)
	if err != nil {
		hasPidfd = false
		fd, err = unix.FanotifyInit(
			unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC,
			eventFlags,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w (needs CAP_SYS_ADMIN / root)", err)
	}

	w := &FanotifyWatcher{
		cfg:        cfg,
		log:        lg,
		fd:         fd,
		hasPidfd:   hasPidfd,
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
		err = unix.FanotifyMark(fd,
			unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
			mask, unix.AT_FDCWD, abs)
		if err != nil {
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

func (w *FanotifyWatcher) HasPidfd() bool { return w.hasPidfd }

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

// extractPidfd walks the variable-length info records that follow the event
// metadata, looking for a FAN_EVENT_INFO_TYPE_PIDFD entry.
//
//	struct fanotify_event_info_header { __u8 info_type; __u8 pad; __u16 len; }
//	struct fanotify_event_info_pidfd  { hdr; __s32 pidfd; }
//
// Returns -1 when no pidfd info is present (older kernel or kernel-initiated
// event), -1 also for FAN_NOPIDFD / FAN_EPIDFD.
func extractPidfd(buf []byte, infoStart, infoEnd int) int {
	for off := infoStart; off+4 <= infoEnd; {
		infoType := buf[off]
		// buf[off+1] is pad
		infoLen := int(binary.NativeEndian.Uint16(buf[off+2:]))
		if infoLen < 4 || off+infoLen > infoEnd {
			return -1
		}
		if infoType == fanEventInfoTypePidfd && off+8 <= infoEnd {
			raw := int32(binary.NativeEndian.Uint32(buf[off+4:]))
			if raw == fanNoPidfd || raw == fanEPidfd {
				return -1
			}
			return int(raw)
		}
		off += infoLen
	}
	return -1
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
			metaLen := int(meta.Metadata_len)
			if evtLen < metaSize || metaLen < metaSize || off+evtLen > nb {
				break
			}

			pidfd := -1
			if w.hasPidfd && evtLen > metaLen {
				pidfd = extractPidfd(buf, off+metaLen, off+evtLen)
			}

			handled := false
			if meta.Fd >= 0 {
				path, lerr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
				if lerr == nil && w.inScope(path) && !w.ignored(path) {
					w.handle(path, meta.Mask, uint32(meta.Pid), pidfd)
					handled = true // handle now owns pidfd
				}
				unix.Close(int(meta.Fd))
			}
			if !handled && pidfd >= 0 {
				unix.Close(pidfd)
			}
			off += evtLen
		}
	}
}

func (w *FanotifyWatcher) handle(path string, mask uint64, pid uint32, pidfd int) {
	_ = mask // currently only FAN_CLOSE_WRITE subscribed
	p := &fanPending{pid: pid, pidfd: pidfd}
	w.mu.Lock()
	if old, ok := w.debounce[path]; ok {
		if old.timer.Stop() {
			// Stopped before firing — its pidfd is unclaimed; release it.
			if old.pidfd >= 0 {
				unix.Close(old.pidfd)
			}
		}
		// else: old.timer's goroutine is already running; the supersede
		// check in process() will detect the replacement and close old.pidfd
		// via its own defer. We must NOT close it here or we'd race that.
	}
	p.timer = time.AfterFunc(w.debDur, func() {
		w.process(path, p)
	})
	w.debounce[path] = p
	w.mu.Unlock()
}

func (w *FanotifyWatcher) process(path string, p *fanPending) {
	// Always release our pidfd before returning. As long as we hold it,
	// the kernel keeps p.pid reserved against reuse, so /proc reads below
	// are guaranteed to be about the right task.
	defer func() {
		if p.pidfd >= 0 {
			unix.Close(p.pidfd)
		}
	}()

	w.mu.Lock()
	cur, ok := w.debounce[path]
	if !ok || cur != p {
		// A newer event arrived after our timer fired but before we got the
		// lock — that newer pending has its own pidfd. Drop ours and bail.
		w.mu.Unlock()
		return
	}
	delete(w.debounce, path)
	prev, hadPrev := w.state[path]
	w.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
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
	editor := loadProcInfo(int(p.pid))
	editor.PID = int(p.pid)

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
	attachEditor(&evt, editor)
	w.log.Log(evt)
}

func (w *FanotifyWatcher) Close() error {
	w.mu.Lock()
	for _, p := range w.debounce {
		if p.timer.Stop() && p.pidfd >= 0 {
			unix.Close(p.pidfd)
		}
		// If Stop returned false, the running process() goroutine will
		// close p.pidfd via its own defer.
	}
	w.debounce = map[string]*fanPending{}
	w.mu.Unlock()
	return unix.Close(w.fd)
}
