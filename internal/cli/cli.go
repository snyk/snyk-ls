package cli

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/cli/auth"
)

type SnykCli struct {
	authenticator *auth.Authenticator
}

var Mutex = &sync.RWMutex{}

func NewExecutor(authenticator *auth.Authenticator) Executor {
	return &SnykCli{
		authenticator: authenticator,
	}
}

type Executor interface {
	Execute(cmd []string, workingDir string) (resp []byte, err error)
	ExpandParametersFromConfig(base []string) []string
	HandleErrors(ctx context.Context, output string, err error) (fail bool)
}

func (c SnykCli) Execute(cmd []string, workingDir string) (resp []byte, err error) {
	Mutex.RLock()
	defer Mutex.RUnlock()
	method := "SnykCli.Execute"
	log.Info().Str("method", method).Interface("cmd", cmd).Msg("calling Snyk CLI")
	output, err := c.doExecute(cmd, workingDir, true)
	log.Trace().Str("method", method).Str("response", string(output))
	return output, err
}

func (c SnykCli) doExecute(cmd []string, workingDir string, firstAttempt bool) ([]byte, error) {
	command := c.getCommand(cmd, workingDir)
	output, err := command.CombinedOutput()
	if err != nil {
		ctx := context.Background()
		shouldRetry := c.HandleErrors(ctx, string(output), err)
		if firstAttempt && shouldRetry {
			output, err = c.doExecute(cmd, workingDir, false)
		}
	}
	return output, err
}

func (c SnykCli) getCommand(cmd []string, workingDir string) *exec.Cmd {
	command := exec.Command(cmd[0], cmd[1:]...)
	command.Dir = workingDir
	cliEnv := c.addConfigValuesToEnv(os.Environ())
	command.Env = cliEnv
	log.Trace().Str("method", "getCommand").Interface("command", command).Interface("env", command.Env).Str("dir", command.Dir).Send()
	return command
}

func (c SnykCli) addConfigValuesToEnv(env []string) (updatedEnv []string) {
	updatedEnv = env

	organization := config.CurrentConfig().GetOrganization()
	if organization != "" {
		updatedEnv = append(updatedEnv, "SNYK_CFG_ORG="+organization)
	}

	endpoint := config.CurrentConfig().CliSettings().Endpoint
	if endpoint != "" {
		updatedEnv = append(updatedEnv, "SNYK_API="+endpoint)
	}

	updatedEnv = append(updatedEnv, "SNYK_TOKEN="+config.CurrentConfig().Token())
	return
}

func (c SnykCli) ExpandParametersFromConfig(base []string) []string {
	var additionalParams []string
	settings := config.CurrentConfig().CliSettings()
	if settings.Insecure {
		additionalParams = append(additionalParams, "--insecure")
	}

	if len(settings.AdditionalParameters) > 0 {
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
		c.authenticator.Authenticate(ctx)
		return true
	}
	return false
}

type TestExecutor struct {
	ExecuteResponse string
}

func NewTestExecutor() *TestExecutor {
	return &TestExecutor{ExecuteResponse: "{}"}
}

func (t TestExecutor) Execute(cmd []string, workingDir string) (resp []byte, err error) {
	return []byte(t.ExecuteResponse), err
}

func (t TestExecutor) ExpandParametersFromConfig(base []string) []string {
	return nil
}

func (t TestExecutor) HandleErrors(ctx context.Context, output string, err error) (fail bool) {
	return false
}
