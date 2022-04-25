package cli

import (
	"os/exec"

	"github.com/rs/zerolog/log"
)

type SnykCli struct{}

type Executor interface {
	Execute(cmd []string) (resp []byte, err error)
}

func (c SnykCli) Execute(cmd []string) (resp []byte, err error) {
	log.Info().Str("method", "SnykCli.Execute").Interface("cmd", cmd).Msg("calling Snyk CLI")
	command := exec.Command(cmd[0], cmd[1:]...)
	output, err := command.CombinedOutput()
	log.Trace().Str("method", "SnykCli.Execute").Str("response", string(output))
	return output, err
}
