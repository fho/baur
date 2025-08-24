package landlock

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/simplesurance/baur/v5/internal/fs"
)

// FSRuleset restricts read and/or write access to filesystem paths.
// By default read and write access is blocked.
type FSRuleset struct {
	filedescriptor uintptr
}

// fsRights are the landlock operations that are denied/allowed
// Only include landlock V1 rules
// FIXME: SOME OF THESE AREN'T FOR LANDLOCK VERSION 1, see landlock(7).
// const fsRights uint64 = unix.LANDLOCK_ACCESS_FS_IOCTL_DEV |
//
//	unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
//	unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
//	unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
//	unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
//	unix.LANDLOCK_ACCESS_FS_MAKE_REG |
//	unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
//	unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
//	unix.LANDLOCK_ACCESS_FS_READ_DIR |
//	unix.LANDLOCK_ACCESS_FS_READ_FILE |
//	unix.LANDLOCK_ACCESS_FS_REFER |
//	unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
//	unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
//	unix.LANDLOCK_ACCESS_FS_TRUNCATE |
//	unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
//	unix.LANDLOCK_ACCESS_FS_EXECUTE
const fsRights uint64 = unix.LANDLOCK_ACCESS_FS_READ_DIR |
	unix.LANDLOCK_ACCESS_FS_READ_FILE

// fileRights are all landlock access rights that are applied to files, these
// are all except the directory specific ones.
const fileRights uint64 = fsRights &^ (unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
	unix.LANDLOCK_ACCESS_FS_READ_DIR |
	unix.LANDLOCK_ACCESS_FS_REMOVE_DIR)

func NewFSRuleset() (*FSRuleset, error) {
	const rulesetAttrSize = 24

	attr := unix.LandlockRulesetAttr{
		Access_fs: fsRights,
	}

	r, _, err := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		rulesetAttrSize,
		version,
	)
	if err != 0 {
		return nil, errnoToError(err)
	}

	return &FSRuleset{filedescriptor: r}, nil
}

func accessRights(path string) (uint64, error) {
	isDir, err := fs.IsDir(path)
	if err != nil {
		return 0, err
	}

	if isDir {
		return fsRights, nil
	}

	return fileRights, nil
}

// Allow adds a rule to allow access to the given file or directory.
// If path is a directory, rights are applied to all directories and paths
// beneath it.
func (rs *FSRuleset) Allow(path string) error {
	perms, err := accessRights(path)
	if err != nil {
		return err
	}

	f, err := syscall.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(f)

	attr := unix.LandlockPathBeneathAttr{
		Allowed_access: perms,
		Parent_fd:      int32(f),
	}

	_, _, sysErr := unix.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		rs.filedescriptor,
		unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&attr)),
		0,
		0,
		0,
	)
	if sysErr != 0 {
		return errnoToError(sysErr)
	}

	return nil
}

// Restrict limits the calling process to the operations allowed by the ruleset.
func (rs *FSRuleset) Restrict() error {
	err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("prctl failed: %w", err)
	}
	_, _, sysErr := unix.Syscall(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		rs.filedescriptor,
		0,
		0,
	)

	return errnoToError(sysErr)
}
