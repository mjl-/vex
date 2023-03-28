//go:build !windows

package main

import (
	"io/fs"
	"os"
	"syscall"
)

var umask int

func init() {
	umask = syscall.Umask(0)
	syscall.Umask(umask)
}

func setBlobPermissions(f *os.File) error {
	return f.Chmod(fs.FileMode(0640 &^ umask))
}
