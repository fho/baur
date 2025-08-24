//go:build linux

package exec

import (
	"fmt"
	"os"
	"syscall"

	"github.com/simplesurance/baur/v5/internal/landlock"
)

type CmdSandboxed struct {
	Name string
	Args []string
	Dir  string
	Env  []string

	AllowedFSAccessPaths []string
}

func (c *CmdSandboxed) Exec() error {
	rs, err := landlock.NewFSRuleset()
	if err != nil {
		return fmt.Errorf("creating landlock ruleset failed: %w", err)
	}

	for _, p := range c.AllowedFSAccessPaths {
		// FIXME: Add READ_DIR rights for all directories from that we allow files
		err := rs.Allow(p)
		if err != nil {
			return fmt.Errorf("adding landlock rule to permit fs access to %q failed: %w", p, err)
		}
	}

	if err := rs.Restrict(); err != nil {
		return fmt.Errorf("restricting landlock file access failed: %w", err)
	}

	if err := os.Chdir(c.Dir); err != nil {
		return err
	}

	err = syscall.Exec(c.Name, c.Args, c.Env)
	if err != nil {
		return fmt.Errorf("exec failed: %w", err)
	}

	return nil
}
