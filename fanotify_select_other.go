//go:build !linux

package main

// tryFanotify is a no-op on non-Linux platforms. main.go always falls back
// to the fsnotify backend.
func tryFanotify(_ *Config, _ *Logger) (Backend, error) { return nil, nil }
