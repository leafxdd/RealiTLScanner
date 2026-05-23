//go:build windows

package output

import (
	"os"
	"syscall"
	"unsafe"
)

func enableVirtualTerminal() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")

	const ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
	// Enable VT on both stdout (table/color) and stderr (LiveLog cursor moves).
	stdoutOK := enableVT(getConsoleMode, setConsoleMode, syscall.Handle(os.Stdout.Fd()), ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	enableVT(getConsoleMode, setConsoleMode, syscall.Handle(os.Stderr.Fd()), ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	if !stdoutOK {
		colorEnabled = false
	}
}

func enableVT(get, set *syscall.LazyProc, h syscall.Handle, flag uint32) bool {
	var mode uint32
	r, _, _ := get.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return false
	}
	r, _, _ = set.Call(uintptr(h), uintptr(mode|flag))
	return r != 0
}
