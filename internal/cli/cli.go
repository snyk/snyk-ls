package cli

import (
	"context"
	"os"
	"os/exec"
	"sync"

	"github.com/snyk/snyk-ls/config/environment"
)

type SnykCli struct{}

type Settings struct {
	Insecure             bool
	Endpoint             string
	AdditionalParameters []string
}

var CurrentSettings Settings
var Mutex = &sync.Mutex{}
var logger = environment.Logger

type Executor interface {
	Execute(ctx context.Context, cmd []string) (resp []byte, err error)
}

func (c SnykCli) Execute(ctx context.Context, cmd []string) (resp []byte, err error) {
	Mutex.Lock()
	defer Mutex.Unlock()
	logger.
		WithField("method", "SnykCli.Execute").
		WithField("cmd", cmd).
		Info(ctx, "calling Snyk CLI")
	command := exec.Command(cmd[0], cmd[1:]...)
	output, err := command.CombinedOutput()
	logger.
		WithField("method", "SnykCli.Execute").
		WithField("response", string(output)).
		Trace(ctx, "CLI output")
	return output, err
}

func ExpandParametersFromConfig(ctx context.Context, base []string) []string {
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
			logger.
				WithField("method", "ExpandParametersFromConfig").
				WithError(err).
				Error(ctx, "couldn't set endpoint in environment")
		}
	}
	return append(base, additionalParams...)
}
