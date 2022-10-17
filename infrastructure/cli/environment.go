package cli

import "github.com/snyk/snyk-ls/application/config"

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

// Returns the input array with additional variables used in the CLI run in the form of "key=value".
// Since we append, our values are overwriting existing env variables (because exec.Cmd.Env chooses the last value
// in case of key duplications).
// appendToken indicates whether we should append the token or not. No token should be appended in cases such as authentication.
func AppendCliEnvironmentVariables(currentEnv []string, appendToken bool) (updatedEnv []string) {
	updatedEnv = currentEnv

	currentConfig := config.CurrentConfig()
	organization := currentConfig.GetOrganization()
	if organization != "" {
		updatedEnv = append(updatedEnv, OrganizationEnvVar+"="+organization)
	}

	if appendToken {
		updatedEnv = append(updatedEnv, TokenEnvVar+"="+currentConfig.Token())
	}
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
