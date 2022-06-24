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
	authenticator  *auth.Authenticator
}

var Mutex = &sync.Mutex{}

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
	method := "SnykCli.Execute"
	log.Info().Str("method", method).Interface("cmd", cmd).Msg("calling Snyk CLI")
	if isIacCommand(cmd) {
		Mutex.Lock()
	}

	command := c.getCommand(cmd, workingDir)
	output, err := command.CombinedOutput()
	if isIacCommand(cmd) {
		Mutex.Unlock()
	}
	if err != nil {
		ctx := context.Background()
		retry := c.HandleErrors(ctx, string(output), err)
		// recurse
		if c.recursionLevel == 0 && retry {
			c.recursionLevel++
			output, err = c.Execute(cmd, workingDir)
		}
	}
	log.Trace().Str("method", method).Str("response", string(output))
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

	// always add token
	updatedEnv = append(updatedEnv, "SNYK_TOKEN="+config.CurrentConfig().Token())
	return
}

func isIacCommand(cmd []string) bool {
	return len(cmd) > 1 && cmd[1] == "iac"
}

func (c SnykCli) ExpandParametersFromConfig(base []string) []string {
	var additionalParams []string
	settings := config.CurrentConfig().CliSettings()
	if settings.Insecure {
		additionalParams = append(additionalParams, "--insecure")
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
