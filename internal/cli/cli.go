package cli

import (
	"os"
	"os/exec"
	"sync"

	"github.com/rs/zerolog/log"
)

type SnykCli struct{}

type Settings struct {
	Insecure             bool
	Endpoint             string
	AdditionalParameters []string
}

var CurrentSettings Settings
var Mutex = &sync.Mutex{}

type Executor interface {
	Execute(cmd []string) (resp []byte, err error)
}

func (c SnykCli) Execute(cmd []string) (resp []byte, err error) {
	Mutex.Lock()
	defer Mutex.Unlock()
	log.Info().Str("method", "SnykCli.Execute").Interface("cmd", cmd).Msg("calling Snyk CLI")
	command := exec.Command(cmd[0], cmd[1:]...)
	output, err := command.CombinedOutput()
	log.Trace().Str("method", "SnykCli.Execute").Str("response", string(output))
	return output, err
}

func CliCmd(base []string) []string {
	var additionalParams []string
	if CurrentSettings.Insecure {
		additionalParams = append(additionalParams, "--insecure")
	}
	if len(CurrentSettings.AdditionalParameters) > 0 {
		additionalParams = append(additionalParams, CurrentSettings.AdditionalParameters...)
	}
	if CurrentSettings.Endpoint != "" {
		err := os.Setenv("SNYK_API", CurrentSettings.Endpoint)
		if err != nil {
			log.Err(err).Msg("couldn't set endpoint in environment")
		}
	}
	return append(base, additionalParams...)
}
