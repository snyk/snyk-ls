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

// TestConstructSettingsFromConfig_AllFieldsPopulated verifies that all template-relevant
// settings are populated by ConstructSettingsFromConfig as a map keyed by pflag names.
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
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.TokenAuthentication))
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingProxyInsecure), true)

	settings, folderConfigs := ConstructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))

	t.Run("Authentication Settings", func(t *testing.T) {
		assert.Equal(t, "test-token", settings[types.SettingToken])
		assert.Equal(t, "https://api.test.snyk.io", settings[types.SettingApiEndpoint])
		assert.Equal(t, string(types.TokenAuthentication), settings[types.SettingAuthenticationMethod])
		assert.Equal(t, true, settings[types.SettingProxyInsecure])
	})

	t.Run("Product Settings", func(t *testing.T) {
		assert.Equal(t, true, settings[types.SettingSnykOssEnabled])
		assert.Equal(t, true, settings[types.SettingSnykCodeEnabled])
		assert.Equal(t, true, settings[types.SettingSnykIacEnabled])
		assert.Equal(t, true, settings[types.SettingSnykSecretsEnabled])
	})

	t.Run("Scan Settings", func(t *testing.T) {
		assert.IsType(t, true, settings[types.SettingScanAutomatic])
		assert.Equal(t, true, settings[types.SettingScanNetNew])
	})

	t.Run("Severity Filter", func(t *testing.T) {
		assert.IsType(t, true, settings[types.SettingSeverityFilterCritical])
		assert.IsType(t, true, settings[types.SettingSeverityFilterHigh])
		assert.IsType(t, true, settings[types.SettingSeverityFilterMedium])
		assert.IsType(t, true, settings[types.SettingSeverityFilterLow])
	})

	t.Run("Issue View", func(t *testing.T) {
		assert.IsType(t, true, settings[types.SettingIssueViewOpenIssues])
		assert.IsType(t, true, settings[types.SettingIssueViewIgnoredIssues])
	})

	t.Run("CLI Settings", func(t *testing.T) {
		assert.NotNil(t, settings[types.SettingCliPath])
		assert.Equal(t, true, settings[types.SettingAutomaticDownload])
		assert.NotNil(t, settings[types.SettingBinaryBaseUrl])
	})

	t.Run("Trusted Folders", func(t *testing.T) {
		tf, ok := settings[types.SettingTrustedFolders].([]string)
		require.True(t, ok)
		assert.NotNil(t, tf)
	})

	t.Run("Folder Configs", func(t *testing.T) {
		require.NotNil(t, folderConfigs)
	})
}

// TestConstructSettingsFromConfig_FolderConfigs verifies folder configs initialization
func TestConstructSettingsFromConfig_FolderConfigs(t *testing.T) {
	engine := testutil.UnitTest(t)

	// Without workspace, folderConfigs should be empty but not nil
	_, folderConfigs := ConstructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))
	require.NotNil(t, folderConfigs)
	assert.Empty(t, folderConfigs)
}

// TestConstructSettingsFromConfig_TrustedFolders verifies trusted folders are properly populated
func TestConstructSettingsFromConfig_TrustedFolders(t *testing.T) {
	t.Run("Empty trusted folders", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		conf := engine.GetConfiguration()
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{})

		settings, _ := ConstructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))

		tf, ok := settings[types.SettingTrustedFolders].([]string)
		require.True(t, ok)
		assert.Empty(t, tf)
	})

	t.Run("Multiple trusted folders", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		conf := engine.GetConfiguration()
		conf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{
			"/Users/test/project-1",
			"/Users/test/project-2",
		})

		settings, _ := ConstructSettingsFromConfig(engine, testutil.DefaultConfigResolver(engine))

		tf, ok := settings[types.SettingTrustedFolders].([]string)
		require.True(t, ok)
		require.Len(t, tf, 2)
		assert.Equal(t, "/Users/test/project-1", tf[0])
		assert.Equal(t, "/Users/test/project-2", tf[1])
	})
}
