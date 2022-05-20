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
	cwd, _ := os.Getwd()
	defer func(dir string) {
		_ = os.Chdir(dir)
	}(cwd)
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
	settings := config.CurrentConfig().CliSettings()
	if settings.Insecure {
		additionalParams = append(additionalParams, "--insecure")
	}

	organization := config.CurrentConfig().GetOrganization()
	if organization != "" {
		err := os.Setenv("SNYK_CFG_ORG", organization)
		if err != nil {
			log.Err(err).Msg("couldn't add organization to environment")
		}
	}

	if len(settings.AdditionalParameters) > 0 {
		additionalParams = append(additionalParams, settings.AdditionalParameters...)
	}
	if settings.Endpoint != "" {
		err := os.Setenv("SNYK_API", settings.Endpoint)
		if err != nil {
			log.Err(err).Msg("couldn't add endpoint to environment")
		}
	}
	return append(base, additionalParams...)
}
