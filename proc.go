package main

// ProcessInfo describes a process that had a file open at the moment we asked.
//
// Detection is best-effort: short writes (open-write-close) usually finish
// before the watcher gets the chance to scan, especially with atomic-write
// editors that work on a tempfile and rename. When that happens an empty
// slice is returned and the watcher falls back to the file-owner field.
type ProcessInfo struct {
	PID  int
	User string // username (Linux) or DOMAIN\user (Windows)
	Name string // short process name / Win32 image name
	Exe  string // full path to the executable, when resolvable
}
