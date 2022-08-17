package cli

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

const (
	OrganizationEnvVar                  = "SNYK_CFG_ORG"
	ApiEnvVar                           = "SNYK_API"
	TokenEnvVar                         = "SNYK_TOKEN"
	DisableAnalyticsEnvVar              = "SNYK_CFG_DISABLE_ANALYTICS"
	IntegrationNameEnvVarKey            = "SNYK_INTEGRATION_NAME"
	IntegrationVersionEnvVarKey         = "SNYK_INTEGRATION_VERSION"
	IntegrationEnvironmentEnvVarKey     = "SNYK_INTEGRATION_ENVIRONMENT"
	IntegrationEnvironmentVersionEnvVar = "SNYK_INTEGRATION_ENVIRONMENT_VERSION"
	IntegrationEnvironmentEnvVarValue   = "language-server"
)

type SnykCli struct {
	authenticator snyk.AuthenticationService
	errorReporter error_reporting.ErrorReporter
	analytics     ux.Analytics
}

var Mutex = &sync.Mutex{}

func NewExecutor(authenticator snyk.AuthenticationService, errorReporter error_reporting.ErrorReporter, analytics ux.Analytics) Executor {
	return &SnykCli{
		authenticator,
		errorReporter,
		analytics,
	}
}

type Executor interface {
	Execute(cmd []string, workingDir string) (resp []byte, err error)
	ExpandParametersFromConfig(base []string) []string
	HandleErrors(ctx context.Context, output string) (fail bool)
}

func (c SnykCli) Execute(cmd []string, workingDir string) (resp []byte, err error) {
	method := "SnykCli.Execute"
	log.Info().Str("method", method).Interface("cmd", cmd).Str("workingDir", workingDir).Msg("calling Snyk CLI")
	output, err := c.doExecute(cmd, workingDir, true)
	log.Trace().Str("method", method).Str("response", string(output))
	return output, err
}

func (c SnykCli) doExecute(cmd []string, workingDir string, firstAttempt bool) ([]byte, error) {
	command := c.getCommand(cmd, workingDir)
	output, err := command.Output()
	if err != nil {
		ctx := context.Background()
		shouldRetry := c.HandleErrors(ctx, string(output))
		if firstAttempt && shouldRetry {
			output, err = c.doExecute(cmd, workingDir, false)
		}
	}
	return output, err
}

func (c SnykCli) getCommand(cmd []string, workingDir string) *exec.Cmd {
	command := exec.Command(cmd[0], cmd[1:]...)
	command.Dir = workingDir
	cliEnv := appendCliEnvironmentVariables(os.Environ())
	command.Env = cliEnv
	log.Debug().Str("method", "getCommand").Interface("command", command).Send()
	return command
}

// Returns the input array with additional variables used in the CLI run in the form of "key=value".
// Since we append, our values are overwriting existing env variables (because exec.Cmd.Env chooses the last value
// in case of key duplications).
func appendCliEnvironmentVariables(currentEnv []string) (updatedEnv []string) {
	updatedEnv = currentEnv

	currentConfig := config.CurrentConfig()
	organization := currentConfig.GetOrganization()
	if organization != "" {
		updatedEnv = append(updatedEnv, OrganizationEnvVar+"="+organization)
	}

	updatedEnv = append(updatedEnv, TokenEnvVar+"="+currentConfig.Token())
	if currentConfig.SnykApi() != "" {
		updatedEnv = append(updatedEnv, ApiEnvVar+"="+currentConfig.SnykApi())
	}
	if !currentConfig.IsTelemetryEnabled() {
		updatedEnv = append(updatedEnv, DisableAnalyticsEnvVar+"=1")
	}

	if currentConfig.IntegrationName() != "" {
		updatedEnv = append(updatedEnv, IntegrationNameEnvVarKey+"="+currentConfig.IntegrationName())
		updatedEnv = append(updatedEnv, IntegrationVersionEnvVarKey+"="+currentConfig.IntegrationVersion())
	}
	updatedEnv = append(updatedEnv, IntegrationEnvironmentEnvVarKey+"="+IntegrationEnvironmentEnvVarValue)
	updatedEnv = append(updatedEnv, IntegrationEnvironmentVersionEnvVar+"="+config.Version)

	return
}

// todo no need to export that, we could have a simpler interface that looks more like an actual CLI
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

func (c SnykCli) HandleErrors(ctx context.Context, output string) (fail bool) {
	if strings.Contains(output, "`snyk` requires an authenticated account. Please run `snyk auth` and try again.") {
		log.Info().Msg("Snyk failed to obtain authentication information. Trying to authenticate again...")
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Snyk failed to obtain authentication information, trying to authenticate again. This could open a browser window."})

		token, err := c.authenticator.Provider().Authenticate(ctx)
		if token == "" || err != nil {
			log.Error().Err(err).Msg("Failed to authenticate. Terminating server.")
			c.errorReporter.CaptureError(err)
			os.Exit(1) // terminate server since unrecoverable from authentication error
		}

		c.authenticator.UpdateToken(token, true)
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

func (t TestExecutor) HandleErrors(ctx context.Context, output string) (fail bool) {
	return false
}
