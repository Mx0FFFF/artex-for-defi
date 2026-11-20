//go:build !windows

package agent

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

func configureDeFiProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// On cancellation/timeout, SIGTERM the whole process group first so the
	// Python wrapper gets a chance to reap the forge/solc subprocess it detached
	// into its own session. Without this cooperative step the heavy compiler
	// keeps running after the task is gone (an SIGKILL to python alone cannot
	// reach a grandchild in a separate session). WaitDelay bounds the wait before
	// os/exec escalates to SIGKILL on the process itself.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
}

func killDeFiProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
