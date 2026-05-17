//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

func FileOwner(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", err
	}
	sid, _, err := sd.Owner()
	if err != nil {
		return "", err
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String(), nil
	}
	if domain != "" {
		return domain + "\\" + account, nil
	}
	return account, nil
}
