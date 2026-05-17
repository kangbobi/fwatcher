//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessesHoldingFile walks /proc/*/fd looking for symlinks pointing at the
// target file. Processes we cannot read (other-user, no root) are skipped
// silently.
func ProcessesHoldingFile(targetPath string) []ProcessInfo {
	abs, err := filepath.Abs(targetPath)
	if err != nil {
		return nil
	}

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	selfPid := os.Getpid()
	var out []ProcessInfo

	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		if pid == selfPid {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == abs {
				out = append(out, loadProcInfo(pid))
				break
			}
		}
	}
	return out
}

func loadProcInfo(pid int) ProcessInfo {
	info := ProcessInfo{PID: pid}

	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		info.Name = strings.TrimSpace(string(b))
	}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		info.Exe = exe
	}
	if f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "Uid:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if u, err := user.LookupId(fields[1]); err == nil {
					info.User = u.Username
				} else {
					info.User = fields[1]
				}
			}
			break
		}
	}
	return info
}
