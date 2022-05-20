package cli

import (
	"os"
	"os/exec"
	"sync"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
)

type SnykCli struct{}

var Mutex = &sync.Mutex{}

type Executor interface {
	Execute(cmd []string) (resp []byte, err error)
}

func (c SnykCli) Execute(cmd []string) (resp []byte, err error) {
	Mutex.Lock()
	defer Mutex.Unlock()
	log.Info().Str("method", "SnykCli.Execute").Interface("cmd", cmd).Msg("calling Snyk CLI")
	err = c.changeToExecutionDir()
	if err != nil {
		return nil, err
	}
	command := exec.Command(cmd[0], cmd[1:]...)
	output, err := command.CombinedOutput()
	log.Trace().Str("method", "SnykCli.Execute").Str("response", string(output))
	return output, err
}

func (c SnykCli) changeToExecutionDir() (err error) {
	dir := os.TempDir()
	if dir == "" {
		dir = xdg.DataHome
	}
	if dir != "" {
		err = os.Chdir(dir)
	}
	return err
}

func ExpandParametersFromConfig(base []string) []string {
	var additionalParams []string
	settings := config.CurrentConfig.CliSettings()
	if settings.Insecure {
		additionalParams = append(additionalParams, "--insecure")
	}
	if len(settings.AdditionalParameters) > 0 {
		additionalParams = append(additionalParams, settings.AdditionalParameters...)
	}
	if settings.Endpoint != "" {
		err := os.Setenv("SNYK_API", settings.Endpoint)
		if err != nil {
			log.Err(err).Msg("couldn't set endpoint in environment")
		}
	}
	return append(base, additionalParams...)
}
