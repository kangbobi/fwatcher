//go:build !linux && !windows

package main

// ProcessesHoldingFile is unimplemented on this OS — returns an empty slice
// so callers fall back to the file-owner field.
func ProcessesHoldingFile(_ string) []ProcessInfo { return nil }
