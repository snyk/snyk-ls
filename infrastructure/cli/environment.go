package cli

import "github.com/snyk/snyk-ls/application/config"

// Returns the input array with additional variables used in the CLI run in the form of "key=value".
// Since we append, our values are overwriting existing env variables (because exec.Cmd.Env chooses the last value
// in case of key duplications).
func AppendCliEnvironmentVariables(currentEnv []string) (updatedEnv []string) {
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
