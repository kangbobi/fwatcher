//go:build linux

package main

import "os"

// tryFanotify returns a fanotify-backed Backend when:
//
//	cfg.Backend == "fanotify" → always try (error if it fails)
//	cfg.Backend == "auto"     → try iff running as root (CAP_SYS_ADMIN proxy)
//	cfg.Backend == "fsnotify" → return (nil, nil) so caller uses fsnotify
//
// Returning (nil, nil) means "skip silently". Returning (nil, err) means
// "we tried and failed" — main.go logs and falls back unless the user pinned
// the backend explicitly.
func tryFanotify(cfg *Config, lg *Logger) (Backend, error) {
	switch cfg.Backend {
	case "fsnotify":
		return nil, nil
	case "auto", "":
		if os.Geteuid() != 0 {
			return nil, nil
		}
	case "fanotify":
		// proceed regardless of euid; fanotify_init will fail if no privilege
	default:
		return nil, nil
	}
	return NewFanotifyWatcher(cfg, lg)
}
