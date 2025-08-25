package command

import (
	"os"

	"github.com/simplesurance/baur/v5/internal/exec"
	"github.com/simplesurance/baur/v5/pkg/baur"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(&newShellCmd().Command)
}

type shellCmd struct {
	cobra.Command
	shellCmd string
}

func newShellCmd() *shellCmd {
	cmd := shellCmd{
		Command: cobra.Command{
			Use:   "shell TASK-ID",
			Short: "Open a shell in the sandboxed environment of the app",
			// FIXME: only allow 1 exactly 1 target argument
			ValidArgsFunction: newCompleteTargetFunc(completeTargetFuncOpts{
				withoutWildcards: true,
				withoutPaths:     true,
				withoutAppNames:  true,
			}),
		},
	}

	cmd.Flags().StringVarP(&cmd.shellCmd, "shell", "s", "bash",
		"Shell Command that is executed")
	cmd.Run = cmd.run

	return &cmd
}

func (c *shellCmd) run(cmd *cobra.Command, args []string) {
	// FIXME: Ensure it works with tasks having taskstatus files, resolve
	// and create them(??)
	repo := mustFindRepository()
	vcsState := mustGetRepoState(repo.Path)
	task := mustArgToTask(repo, vcsState, args[0])
	inputResolver := baur.NewInputResolver(
		vcsState,
		repo.Path,
		nil,
		false, // FIXME: false
	)

	// FIXME: DO NOT DO THIS:
	task.Command = []string{c.shellCmd}
	inputs, err := inputResolver.Resolve(ctx, task)
	exitOnErr(err)

	// runner := baur.NewTaskRunner(nil, true)
	sbCmd := exec.CmdSandboxed{
		// FIXME: use c.shellCmd: ,
		Name: "/bin/bash", // FIXME: use lookup, etc
		Dir:  task.Directory,
		Env:  os.Environ(), // FIXME: needed?
		AllowedFSAccessPaths: append(baur.InputsToFSPaths(inputs.Inputs()),
			"/usr/bin/",
			"/usr/lib/",
			"/usr/lib64/",
			"/etc/",
			"/dev/",
			"/proc/",
			"/sys/",
			"/usr/",
			"/var/",
			"/home/fho/.local",
			"/home/fho/.config",
			"/run",
			task.Directory,
		),
	}
	exitOnErr(sbCmd.Exec())
}
