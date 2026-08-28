//go:build windows

// Platform-specific kill implementation for Windows. Uses
// OpenProcess + TerminateProcess from the Win32 API. The
// cross-platform pid -> HANDLE mapping is handled in this
// file; the rest of the kinds package is unchanged.
//
// Note: this implementation requires the agent to be running
// as a service with SE_DEBUG_NAME or as the target user
// (Windows refuses OpenProcess on another session without
// it). v1.2 Slice 3 (ADR-007) ships this; Slice 1 (this
// file) compiles for the windows GOOS to prove the build
// matrix works end-to-end.
package kinds

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modkernel32              = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess          = modkernel32.NewProc("OpenProcess")
	procTerminateProcess     = modkernel32.NewProc("TerminateProcess")
	procCloseHandle          = modkernel32.NewProc("CloseHandle")
)

// PROCESS_TERMINATE = 0x0001 - we only need terminate rights.
const processTerminate = 0x0001

// platformKill terminates the given pid on Windows by
// opening a process handle with PROCESS_TERMINATE and
// calling TerminateProcess. The handle is closed after
// the call regardless of outcome.
//
// Failure modes:
//   - OpenProcess returns 0: insufficient privileges
//     (cross-session or protected process)
//   - TerminateProcess returns 0: handle is valid but the
//     kernel refused (almost always a protected process)
func platformKill(pid int) error {
	// OpenProcess(handleRight, inheritHandle, pid)
	handle, _, _ := procOpenProcess.Call(
		uintptr(processTerminate),
		uintptr(0),
		uintptr(pid),
	)
	if handle == 0 {
		return fmt.Errorf("OpenProcess(%d) failed: insufficient privileges or invalid pid", pid)
	}
	defer procCloseHandle.Call(handle)

	// TerminateProcess(handle, exitCode)
	ret, _, _ := procTerminateProcess.Call(
		handle,
		uintptr(1),  // exit code 1
	)
	if ret == 0 {
		// GetLastError for diagnostics.
		err := syscall.GetLastError()
		return fmt.Errorf("TerminateProcess(%d) failed: %v (handle=%x, ptr=%x)",
			pid, err, handle, unsafe.Pointer(nil))
	}
	return nil
}
