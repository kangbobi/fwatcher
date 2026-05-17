package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// Backend is anything that watches the filesystem and produces Events.
type Backend interface {
	Run(ctx context.Context) error
	Close() error
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	lg, err := NewLogger(cfg.LogPath)
	if err != nil {
		log.Fatalf("init logger: %v", err)
	}
	defer lg.Close()

	backend, name, err := selectBackend(cfg, lg)
	if err != nil {
		log.Fatalf("init backend: %v", err)
	}
	defer backend.Close()

	if pf, ok := backend.(interface{ HasPidfd() bool }); ok {
		if pf.HasPidfd() {
			name += " (FAN_REPORT_PIDFD)"
		} else {
			name += " (no pidfd; kernel<5.15 — PID-reuse race possible)"
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lg.Log(Event{EventType: "service_started", Path: cfg.LogPath})
	log.Printf("fwatcher started: backend=%s, %d path(s), recursive=%v, log=%s",
		name, len(cfg.Paths), cfg.Recursive, cfg.LogPath)

	if err := backend.Run(ctx); err != nil {
		log.Fatalf("backend: %v", err)
	}

	lg.Log(Event{EventType: "service_stopped"})
	log.Println("fwatcher stopped")
}

// selectBackend picks fanotify when explicitly requested or when running as
// root on Linux. Falls back to fsnotify everywhere else.
func selectBackend(cfg *Config, lg *Logger) (Backend, string, error) {
	if cfg.Backend != "fsnotify" {
		be, err := tryFanotify(cfg, lg)
		if be != nil {
			return be, "fanotify", nil
		}
		if err != nil && cfg.Backend == "fanotify" {
			return nil, "", err // user explicitly asked for it
		}
		if err != nil {
			log.Printf("fanotify unavailable: %v; falling back to fsnotify", err)
		}
	}
	w, err := NewWatcher(cfg, lg)
	if err != nil {
		return nil, "", err
	}
	return w, "fsnotify", nil
}
