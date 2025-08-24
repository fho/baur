// go:build linux
package baur

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/simplesurance/baur/v5/internal/exec"
)

const baurRunSandboxedSubCmd = "__run_sandboxed"

// func (t *TaskRunner) RunSandboxedCmd(cmd []string, inputs []Input) (*RunResult, error) {
// }

func (t *TaskRunner) RunSandboxed(task *Task, inputs []Input) (*RunResult, error) {
	// FIXME: reduce duplicated code from Run()
	if t.skipAfterError && t.SkipRunsIsEnabled() {
		return nil, ErrTaskRunSkipped
	}
	if t.GitUntrackedFilesFn != nil {
		untracked, err := t.GitUntrackedFilesFn(task.RepositoryRoot)
		if err != nil {
			return nil, err
		}

		if len(untracked) != 0 {
			return nil, &ErrUntrackedGitFilesExist{UntrackedFiles: untracked}
		}
	}

	env, deleteTempTaskInfoFilesFn, err := t.createTaskInfoEnv(context.TODO(), task)
	if err != nil {
		return nil, err
	}
	defer deleteTempTaskInfoFilesFn()

	sbCmd := exec.CmdSandboxed{
		Name:                 task.Command[0],
		Args:                 task.Command[1:],
		Dir:                  task.Directory,
		Env:                  append(os.Environ(), env...),
		AllowedFSAccessPaths: InputsToFSPaths(inputs),
	}

	extraData, err := encodeCmdSb(&sbCmd)
	if err != nil {
		return nil, fmt.Errorf("encoding CmdSandboxed failed: %w", err)
	}

	startTime := time.Now()
	execResult, err := exec.Command("/proc/self/exe", baurRunSandboxedSubCmd).
		Directory(task.Directory).
		LogPrefix(color.YellowString(fmt.Sprintf("%s: ", task))).
		LogFn(t.LogFn).
		Env(append(os.Environ(), env...)).
		ExtraData(extraData).
		Run(context.TODO())
	if err != nil {
		return nil, err
	}

	return &RunResult{
		Result:    execResult,
		StartTime: startTime,
		StopTime:  time.Now(),
	}, nil
}

func encodeCmdSb(cmd *exec.CmdSandboxed) (*bytes.Buffer, error) {
	var buf bytes.Buffer

	err := gob.NewEncoder(&buf).Encode(cmd)
	if err != nil {
		return nil, err
	}

	return &buf, nil
}

func decodeCmdSb(r io.ReadCloser) (*exec.CmdSandboxed, error) {
	var result exec.CmdSandboxed

	err := gob.NewDecoder(r).Decode(&result)
	if err != nil {
		return nil, err
	}

	return &result, err
}
