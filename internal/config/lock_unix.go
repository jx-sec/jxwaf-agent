//go:build unix

package config

import (
	"os"
	"syscall"
)

// lockFile 对文件加排他锁（unix：flock；Windows 平台为 no-op，见 lock_other.go）。
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
