package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Timestamp     string `json:"timestamp"`
	Source        string `json:"source"`
	Host          string `json:"host"`
	EventType     string `json:"event_type"`
	Path          string `json:"path,omitempty"`
	User          string `json:"user,omitempty"`
	SizeBefore    int64  `json:"size_before,omitempty"`
	SizeAfter     int64  `json:"size_after,omitempty"`
	HashBefore    string `json:"hash_before,omitempty"`
	HashAfter     string `json:"hash_after,omitempty"`
	Diff          string `json:"diff,omitempty"`
	DiffTruncated bool   `json:"diff_truncated,omitempty"`
	IsBinary      bool   `json:"is_binary,omitempty"`
	Error         string `json:"error,omitempty"`
}

type Logger struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	host string
}

func NewLogger(path string) (*Logger, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	return &Logger{f: f, enc: json.NewEncoder(f), host: host}, nil
}

func (l *Logger) Log(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.Source == "" {
		e.Source = "fwatcher"
	}
	if e.Host == "" {
		e.Host = l.host
	}
	_ = l.enc.Encode(&e)
	_ = l.f.Sync()
}

func (l *Logger) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}
