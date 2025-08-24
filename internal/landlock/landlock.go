//go:build linux

// Package landlock provides restricting filesystem access for the current
// running process via the Landlock Linux API.
// (https://docs.kernel.org/userspace-api/landlock.html)
package landlock

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// version is the landlock API version that the package uses
// FIXME: which version should we use?
const version = 0

var (
	ErrLandlockDisabled     = errors.New("landlock is supported by the kernel but disabled at boot time")
	ErrLandLockNotSupported = errors.New("landlock is not support by your kernel")
)

// Version returns the landlock version supported by the kernel.
// If landlock is not supported ErrLandlockDisabled or ErrLandLockNotSupported
// is returned.
func Version() (int, error) {
	r, _, err := unix.Syscall(unix.LANDLOCK_CREATE_RULESET_VERSION, uintptr(0), 0, 0)
	if err != 0 {
		return -1, errnoToError(err)
	}

	return int(r), nil
}

// errnoToError converts an Errno Code to a Go error.
func errnoToError(err syscall.Errno) error {
	if err != 0 {
		if errors.Is(err, syscall.EOPNOTSUPP) {
			return ErrLandlockDisabled
		}

		if errors.Is(err, syscall.ENOSYS) {
			return ErrLandLockNotSupported
		}

		return err
	}

	return nil
}
