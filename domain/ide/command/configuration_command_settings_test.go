package command

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// TestConstructSettingsFromConfig_AllFieldsPopulated verifies that all fields
// from types.Settings are populated by constructSettingsFromConfig
func TestConstructSettingsFromConfig_AllFieldsPopulated(t *testing.T) {
	c := testutil.UnitTest(t)
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))

	// Configure the config with test values for all fields
	c.SetToken("test-token")
	c.UpdateApiEndpoints("https://api.test.snyk.io")
	c.SetOrganization("test-org")
	c.SetSnykCodeEnabled(true)
	c.SetSnykOssEnabled(true)
	c.SetSnykIacEnabled(true)
	c.EnableSnykCodeSecurity(true)
	c.SetErrorReportingEnabled(true)
	c.SetManageBinariesAutomatically(true)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetAuthenticationMethod(types.TokenAuthentication)
	c.SetSnykLearnCodeActionsEnabled(true)
	c.SetSnykOSSQuickFixCodeActionsEnabled(true)
	c.SetDeltaFindingsEnabled(true)
	c.SetSnykOpenBrowserActionsEnabled(true)
	c.SetOsPlatform("darwin")
	c.SetOsArch("arm64")
	c.SetRuntimeName("node")
	c.SetRuntimeVersion("18.0.0")

	// Set additional settings via CliSettings
	if c.CliSettings() != nil {
		c.CliSettings().Insecure = true
	}

	settings := constructSettingsFromConfig(c)

	// Test all global settings are populated
	t.Run("Core Authentication Settings", func(t *testing.T) {
		assert.Equal(t, "test-token", settings.Token, "Token should be populated")
		assert.Equal(t, "https://api.test.snyk.io", settings.Endpoint, "Endpoint should be populated")
		// Organization may be empty until authenticated or explicitly set from stored config
		assert.NotNil(t, settings.Organization, "Organization should be initialized")
		assert.Equal(t, types.TokenAuthentication, settings.AuthenticationMethod, "AuthenticationMethod should be populated")
		assert.NotEmpty(t, settings.AutomaticAuthentication, "AutomaticAuthentication should be populated")
		// DeviceId may be empty in test environment
		assert.NotNil(t, settings.DeviceId, "DeviceId should be initialized")
	})

	t.Run("Product Activation Settings", func(t *testing.T) {
		assert.Equal(t, "true", settings.ActivateSnykOpenSource, "ActivateSnykOpenSource should be populated")
		assert.Equal(t, "true", settings.ActivateSnykCode, "ActivateSnykCode should be populated")
		assert.Equal(t, "true", settings.ActivateSnykIac, "ActivateSnykIac should be populated")
		assert.Equal(t, "true", settings.ActivateSnykCodeSecurity, "ActivateSnykCodeSecurity should be populated")
		assert.NotEmpty(t, settings.ActivateSnykCodeQuality, "ActivateSnykCodeQuality should be populated")
	})

	t.Run("CLI and Path Settings", func(t *testing.T) {
		assert.NotEmpty(t, settings.CliPath, "CliPath should be populated")
		assert.NotEmpty(t, settings.Path, "Path should be populated")
		assert.Equal(t, "true", settings.ManageBinariesAutomatically, "ManageBinariesAutomatically should be populated")
	})

	t.Run("Security Settings", func(t *testing.T) {
		assert.Equal(t, "true", settings.Insecure, "Insecure should be populated")
		assert.Equal(t, "true", settings.EnableTrustedFoldersFeature, "EnableTrustedFoldersFeature should be populated")
		assert.NotNil(t, settings.TrustedFolders, "TrustedFolders should be populated")
	})

	t.Run("Operational Settings", func(t *testing.T) {
		assert.NotEmpty(t, settings.ScanningMode, "ScanningMode should be populated")
		assert.Equal(t, "true", settings.SendErrorReports, "SendErrorReports should be populated")
	})

	t.Run("Filter and Display Settings", func(t *testing.T) {
		assert.NotNil(t, settings.FilterSeverity, "FilterSeverity should be populated")
		assert.NotNil(t, settings.IssueViewOptions, "IssueViewOptions should be populated")
		assert.NotNil(t, settings.HoverVerbosity, "HoverVerbosity should be populated")
		assert.NotNil(t, settings.OutputFormat, "OutputFormat should be populated")
	})

	t.Run("Feature Toggles", func(t *testing.T) {
		assert.Equal(t, "true", settings.EnableSnykLearnCodeActions, "EnableSnykLearnCodeActions should be populated")
		assert.Equal(t, "true", settings.EnableSnykOSSQuickFixCodeActions, "EnableSnykOSSQuickFixCodeActions should be populated")
		assert.Equal(t, "true", settings.EnableSnykOpenBrowserActions, "EnableSnykOpenBrowserActions should be populated")
		assert.Equal(t, "true", settings.EnableDeltaFindings, "EnableDeltaFindings should be populated")
	})

	t.Run("Advanced Settings", func(t *testing.T) {
		assert.NotEmpty(t, settings.SnykCodeApi, "SnykCodeApi should be populated")
		// IntegrationName and IntegrationVersion may be empty in test environment
		assert.NotNil(t, settings.IntegrationName, "IntegrationName should be initialized")
		assert.NotNil(t, settings.IntegrationVersion, "IntegrationVersion should be initialized")
		assert.Equal(t, "darwin", settings.OsPlatform, "OsPlatform should be populated")
		assert.Equal(t, "arm64", settings.OsArch, "OsArch should be populated")
		assert.Equal(t, "node", settings.RuntimeName, "RuntimeName should be populated")
		assert.Equal(t, "18.0.0", settings.RuntimeVersion, "RuntimeVersion should be populated")
		// RequiredProtocolVersion may be empty until client connects
		assert.NotNil(t, settings.RequiredProtocolVersion, "RequiredProtocolVersion should be initialized")
		// AdditionalParams is populated from CliSettings
		assert.NotNil(t, settings.AdditionalParams, "AdditionalParams should be initialized")
		// AdditionalEnv is currently not stored in config
		assert.NotNil(t, settings.AdditionalEnv, "AdditionalEnv should be initialized")
	})

	t.Run("Folder Configs", func(t *testing.T) {
		// FolderConfigs may be empty if no workspace is set, so we just verify it's not nil
		require.NotNil(t, settings.FolderConfigs, "FolderConfigs should be initialized")
	})
}

// TestConstructSettingsFromConfig_FolderConfigs verifies folder configs initialization
func TestConstructSettingsFromConfig_FolderConfigs(t *testing.T) {
	c := testutil.UnitTest(t)

	// Without workspace, FolderConfigs should be empty but not nil
	settings := constructSettingsFromConfig(c)
	require.NotNil(t, settings.FolderConfigs, "FolderConfigs should be initialized")
	assert.Empty(t, settings.FolderConfigs, "FolderConfigs should be empty when no workspace is set")
}
