//go:build !windows

package main

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func FileOwner(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", nil
	}
	uid := strconv.Itoa(int(st.Uid))
	u, err := user.LookupId(uid)
	if err != nil {
		return uid, nil
	}
	return u.Username, nil
}
