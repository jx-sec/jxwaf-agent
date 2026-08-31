//go:build !unix

package config

import "os"

// lockFile 非 unix 平台无跨进程锁原语，退化为 no-op（保存路径仍为原子替换）。
func lockFile(f *os.File) error { return nil }

func unlockFile(f *os.File) error { return nil }
