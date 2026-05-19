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

	handle := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	r, _, _ := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		colorEnabled = false
		return
	}
	const ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
	r, _, _ = setConsoleMode.Call(uintptr(handle), uintptr(mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING))
	if r == 0 {
		colorEnabled = false
	}
}
