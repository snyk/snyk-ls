package command

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// TestConstructSettingsFromConfig_AllFieldsPopulated verifies that all fields
// from types.Settings are populated by constructSettingsFromConfig
func TestConstructSettingsFromConfig_AllFieldsPopulated(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	require.NoError(t, types.WaitForDefaultEnv(t.Context(), engine.GetConfiguration()))

	// Configure the config with test values for all fields
	tokenService.SetToken(engine.GetConfiguration(), "test-token")
	config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.test.snyk.io")
	config.SetOrganization(engine.GetConfiguration(), "test-org")
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{
		"/Users/test/trusted-folder-1",
		"/Users/test/trusted-folder-2",
	})
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.TokenAuthentication))
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykLearnCodeActions), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingOsPlatform), "darwin")
	conf.Set(configresolver.UserGlobalKey(types.SettingOsArch), "arm64")
	conf.Set(configresolver.UserGlobalKey(types.SettingRuntimeName), "node")
	conf.Set(configresolver.UserGlobalKey(types.SettingRuntimeVersion), "18.0.0")

	// Set additional settings via config
	if engine != nil {
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingProxyInsecure), true)
	}

	settings := constructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))

	// Test all global settings are populated
	t.Run("Core Authentication Settings", func(t *testing.T) {
		assert.Equal(t, "test-token", settings.Token, "Token should be populated")
		assert.Equal(t, "https://api.test.snyk.io", settings.Endpoint, "Endpoint should be populated")
		// Organization may be empty until authenticated or explicitly set from folderConfig
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
		assert.Equal(t, "true", settings.ActivateSnykSecrets, "ActivateSnykSecrets should be populated")
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
		assert.NotEmpty(t, settings.TrustedFolders, "TrustedFolders should contain at least one entry")
	})

	t.Run("Operational Settings", func(t *testing.T) {
		assert.NotEmpty(t, settings.ScanningMode, "ScanningMode should be populated")
		assert.Equal(t, "true", settings.SendErrorReports, "SendErrorReports should be populated")
	})

	t.Run("Filter and Display Settings", func(t *testing.T) {
		assert.NotNil(t, settings.FilterSeverity, "FilterSeverity should be populated")
		assert.NotNil(t, settings.IssueViewOptions, "IssueViewOptions should be populated")
		assert.NotNil(t, settings.HoverVerbosity, "HoverVerbosity should be populated")
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
		// AdditionalParams is populated from CliAdditionalOssParameters
		assert.NotNil(t, settings.AdditionalParams, "AdditionalParams should be initialized")
		// AdditionalEnv is currently not stored in config
		assert.NotNil(t, settings.AdditionalEnv, "AdditionalEnv should be initialized")
	})

	t.Run("Folder Configs", func(t *testing.T) {
		// FolderConfigs may be empty if no workspace is set, so we just verify it's not nil
		require.NotNil(t, settings.StoredFolderConfigs, "StoredFolderConfigs should be initialized")
	})
}

// TestConstructSettingsFromConfig_FolderConfigs verifies folder configs initialization
func TestConstructSettingsFromConfig_FolderConfigs(t *testing.T) {
	engine := testutil.UnitTest(t)

	// Without workspace, StoredFolderConfigs should be empty but not nil
	settings := constructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))
	require.NotNil(t, settings.StoredFolderConfigs, "StoredFolderConfigs should be initialized")
	assert.Empty(t, settings.StoredFolderConfigs, "StoredFolderConfigs should be empty when no workspace is set")
}

// TestConstructSettingsFromConfig_TrustedFolders verifies trusted folders are properly populated
func TestConstructSettingsFromConfig_TrustedFolders(t *testing.T) {
	t.Run("Empty trusted folders", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		conf := engine.GetConfiguration()
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), false)
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{})

		settings := constructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, "false", settings.EnableTrustedFoldersFeature, "EnableTrustedFoldersFeature should be false")
		assert.NotNil(t, settings.TrustedFolders, "TrustedFolders should be initialized")
		assert.Empty(t, settings.TrustedFolders, "TrustedFolders should be empty when not configured")
	})

	t.Run("Single trusted folder", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		conf := engine.GetConfiguration()
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{
			"/Users/test/trusted-project",
		})

		settings := constructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, "true", settings.EnableTrustedFoldersFeature, "EnableTrustedFoldersFeature should be true")
		require.NotNil(t, settings.TrustedFolders, "TrustedFolders should be initialized")
		require.Len(t, settings.TrustedFolders, 1, "TrustedFolders should contain one folder")
		assert.Equal(t, "/Users/test/trusted-project", settings.TrustedFolders[0], "Trusted folder path should match")
	})

	t.Run("Multiple trusted folders", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		conf := engine.GetConfiguration()
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{
			"/Users/test/project-1",
			"/Users/test/project-2",
			"/home/user/workspace",
		})

		settings := constructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, "true", settings.EnableTrustedFoldersFeature, "EnableTrustedFoldersFeature should be true")
		require.NotNil(t, settings.TrustedFolders, "TrustedFolders should be initialized")
		require.Len(t, settings.TrustedFolders, 3, "TrustedFolders should contain three folders")
		assert.Equal(t, "/Users/test/project-1", settings.TrustedFolders[0], "First trusted folder should match")
		assert.Equal(t, "/Users/test/project-2", settings.TrustedFolders[1], "Second trusted folder should match")
		assert.Equal(t, "/home/user/workspace", settings.TrustedFolders[2], "Third trusted folder should match")
	})

	t.Run("FilePath to string conversion", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		conf := engine.GetConfiguration()
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

		// Test that FilePath type is correctly converted to string
		testPath := types.FilePath("/path/with/special/chars/@#$")
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{testPath})

		settings := constructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))

		require.NotNil(t, settings.TrustedFolders, "TrustedFolders should be initialized")
		require.Len(t, settings.TrustedFolders, 1, "TrustedFolders should contain one folder")
		assert.Equal(t, string(testPath), settings.TrustedFolders[0], "FilePath should be correctly converted to string")
		assert.IsType(t, "", settings.TrustedFolders[0], "TrustedFolders should contain string values")
	})
}
