//go:build windows

package agent

import "os/exec"

func configureDeFiProcessGroup(*exec.Cmd) {}

func killDeFiProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
