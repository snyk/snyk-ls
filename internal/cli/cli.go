package cli

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/cli/auth"
)

type SnykCli struct {
	recursionLevel int
}

var Mutex = &sync.Mutex{}

type Executor interface {
	Execute(cmd []string, workingDir string) (resp []byte, err error)
	ExpandParametersFromConfig(base []string) []string
	HandleErrors(ctx context.Context, output string, err error) (fail bool)
}

func (c SnykCli) Execute(cmd []string, workingDir string) (resp []byte, err error) {
	log.Info().Str("method", "SnykCli.Execute").Interface("cmd", cmd).Msg("calling Snyk CLI")
	Mutex.Lock()
	command := exec.Command(cmd[0], cmd[1:]...)
	command.Dir = workingDir
	output, err := command.CombinedOutput()
	Mutex.Unlock()
	if err != nil {
		ctx := context.Background()
		retry := c.HandleErrors(ctx, string(output), err)
		// recurse
		if c.recursionLevel == 0 && retry {
			c.recursionLevel++
			output, err = c.Execute(cmd, workingDir)
		}
	}
	log.Trace().Str("method", "SnykCli.Execute").Str("response", string(output))
	return output, err
}

func (c SnykCli) ExpandParametersFromConfig(base []string) []string {
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
		additionalParams = append(additionalParams, "--org="+organization)
	}

	if settings.Endpoint != "" {
		err := os.Setenv("SNYK_API", settings.Endpoint)
		if err != nil {
			log.Err(err).Msg("couldn't add endpoint to environment")
		}
	}

	if len(settings.AdditionalParameters) > 0 {
		//additionalParams = append(additionalParams, settings.AdditionalParameters...)
		for _, parameter := range settings.AdditionalParameters {
			if base[1] == "iac" && parameter == "--all-projects" {
				continue
			}
			additionalParams = append(additionalParams, parameter)
		}
	}

	return append(base, additionalParams...)
}

func (c SnykCli) HandleErrors(ctx context.Context, output string, err error) (fail bool) {
	if strings.Contains(output, "`snyk` requires an authenticated account. Please run `snyk auth` and try again.") {
		auth.Authenticate(ctx)
		return true
	}
	return false
}
