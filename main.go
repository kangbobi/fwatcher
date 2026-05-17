package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

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

	w, err := NewWatcher(cfg, lg)
	if err != nil {
		log.Fatalf("init watcher: %v", err)
	}
	defer w.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lg.Log(Event{EventType: "service_started", Path: cfg.LogPath})
	log.Printf("fwatcher started: %d path(s), recursive=%v, log=%s",
		len(cfg.Paths), cfg.Recursive, cfg.LogPath)

	if err := w.Run(ctx); err != nil {
		log.Fatalf("watcher: %v", err)
	}

	lg.Log(Event{EventType: "service_stopped"})
	log.Println("fwatcher stopped")
}
