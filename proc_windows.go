//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessesHoldingFile asks Windows Restart Manager which processes currently
// have the file open. No admin required for files the user can already see.
// Misses fast write-and-close patterns (atomic-replace, scripts) just like
// the Linux /proc scan does.
func ProcessesHoldingFile(targetPath string) []ProcessInfo {
	var session uint32
	sessionKey := make([]uint16, cchRmSessionKey+1)

	if r, _, _ := procRmStartSession.Call(
		uintptr(unsafe.Pointer(&session)),
		0,
		uintptr(unsafe.Pointer(&sessionKey[0])),
	); r != 0 {
		return nil
	}
	defer procRmEndSession.Call(uintptr(session))

	pathPtr, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return nil
	}
	pathSlice := []*uint16{pathPtr}

	if r, _, _ := procRmRegisterResources.Call(
		uintptr(session),
		1,
		uintptr(unsafe.Pointer(&pathSlice[0])),
		0, 0,
		0, 0,
	); r != 0 {
		return nil
	}

	var needed uint32
	var count uint32 = 16
	info := make([]rmProcessInfo, count)
	var reasons uint32

	r, _, _ := procRmGetList.Call(
		uintptr(session),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&info[0])),
		uintptr(unsafe.Pointer(&reasons)),
	)
	// ERROR_MORE_DATA (234) means our buffer was too small; we still got
	// the first `count` entries. Anything else non-zero is a real error.
	if r != 0 && r != 234 {
		return nil
	}

	self := uint32(windows.GetCurrentProcessId())
	var out []ProcessInfo
	for i := uint32(0); i < count; i++ {
		p := info[i]
		if p.Process.DwProcessId == self {
			continue
		}
		out = append(out, ProcessInfo{
			PID:  int(p.Process.DwProcessId),
			Name: windows.UTF16ToString(p.StrAppName[:]),
			User: processUser(p.Process.DwProcessId),
			Exe:  processImagePath(p.Process.DwProcessId),
		})
	}
	return out
}

func processUser(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()

	tu, err := token.GetTokenUser()
	if err != nil {
		return ""
	}
	account, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return tu.User.Sid.String()
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

func processImagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// --- Restart Manager bindings ---

const (
	cchRmMaxAppName  = 255
	cchRmMaxSvcName  = 63
	cchRmSessionKey  = 32
)

type rmFiletime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type rmUniqueProcess struct {
	DwProcessId      uint32
	ProcessStartTime rmFiletime
}

type rmProcessInfo struct {
	Process             rmUniqueProcess
	StrAppName          [cchRmMaxAppName + 1]uint16
	StrServiceShortName [cchRmMaxSvcName + 1]uint16
	ApplicationType     uint32
	AppStatus           uint32
	TSSessionId         uint32
	BRestartable        int32
}

var (
	modRstrtMgr             = windows.NewLazySystemDLL("rstrtmgr.dll")
	procRmStartSession      = modRstrtMgr.NewProc("RmStartSession")
	procRmRegisterResources = modRstrtMgr.NewProc("RmRegisterResources")
	procRmGetList           = modRstrtMgr.NewProc("RmGetList")
	procRmEndSession        = modRstrtMgr.NewProc("RmEndSession")
)
