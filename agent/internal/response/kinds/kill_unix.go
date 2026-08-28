//go:build unix

// Platform-specific kill implementation for unix-like systems
// (Linux, macOS). Uses syscall.Kill. Build tag matches the
// v1.0.0 platform set; v1.2 will add Windows and the windows
// branch is in kill_windows.go.
package kinds

import (
	"syscall"
)

// platformKill sends SIGKILL to the given pid on unix-like
// systems. Caller is responsible for validating the pid
// (KillProcess above checks for pid 1 and self).
func platformKill(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
