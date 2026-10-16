//go:build unix

package reviewer

import (
	"os"

	"golang.org/x/sys/unix"
)

func openStateFile(root *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
	return root.OpenFile(name, flag|unix.O_NOFOLLOW, perm)
}

func lockStateFile(file *os.File, exclusive, nonblocking bool) error {
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	if nonblocking {
		mode |= unix.LOCK_NB
	}
	return unix.Flock(int(file.Fd()), mode)
}

func unlockStateFile(file *os.File) {
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
