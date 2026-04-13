package configuration

import (
	"html/template"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
	"github.com/snyk/snyk-ls/internal/util"
)

func TestConfigHtmlRenderer_GetConfigHtml(t *testing.T) {
	engine := testutil.UnitTest(t)

	// Set up mock workspace with a folder
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/a_folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("a_folder").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)
	assert.NotNil(t, renderer)

	settings := types.Settings{
		Token:                  "test-token",
		Endpoint:               "https://test.snyk.io",
		Organization:           util.Ptr("test-org"),
		Insecure:               "true",
		ActivateSnykOpenSource: "true",
		ActivateSnykCode:       "true",
		AuthenticationMethod:   "oauth",
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: folderPath},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify visible fields in simplified UI
	assert.Contains(t, html, "test-token")
	assert.Contains(t, html, "https://test.snyk.io")
	assert.Contains(t, html, "/path/to/a_folder")
	assert.Contains(t, html, "checked") // Insecure checkbox
	assert.Contains(t, html, `data-config-scope-slot="true"`)

	expectedSettingKeys := []string{
		"snyk_oss_enabled",
		"snyk_code_enabled",
		"snyk_iac_enabled",
		"scan_automatic",
		"enabled_severities_critical",
		"enabled_severities_high",
		"enabled_severities_medium",
		"enabled_severities_low",
		"issue_view_open_issues",
		"issue_view_ignored_issues",
		"risk_score_threshold",
		"scan_net_new",
		"authentication_method",
		"api_endpoint",
		"proxy_insecure",
		"token",
		"cli_path",
		"automatic_download",
		"cli_release_channel",
		"binary_base_url",
		"trusted_folders",
	}

	for _, key := range expectedSettingKeys {
		assert.Contains(t, html, `data-setting-key="`+key+`"`)
	}
	assert.Contains(t, html, "window.__saveIdeConfig__")
	assert.Contains(t, html, "window.getAndSaveIdeConfig")
	assert.Contains(t, html, "window.__ideExecuteCommand__")
	assert.Contains(t, html, "Snyk Code")
	assert.Contains(t, html, "Authentication method")
	assert.Contains(t, html, `id="get-token-link"`)
	assert.Contains(t, html, `id="get-token-link" href="#" class="hidden button-link"`)
	assert.Contains(t, html, `id="token-field-group"`)
	assert.Contains(t, html, `class="form-group hidden"`)
	assert.Contains(t, html, `id="logout-btn" class="secondary hidden"`)
	assert.Contains(t, html, "oauth")
	assert.Contains(t, html, "Scan configuration") // Section header
	assert.Contains(t, html, "Filters and views")  // Section header
	assert.Contains(t, html, "Trust settings")     // Section header
	assert.Contains(t, html, "CLI configuration")  // Section header
	assert.Contains(t, html, "- Project")          // Project tab label
	assert.Contains(t, html, `class="info-box"`)   // Info boxes present
	assert.Contains(t, html, "These settings apply to all projects unless overridden.")
	assert.Contains(t, html, "These settings override the project defaults for this specific project.")
}

func TestConfigHtmlRenderer_LdxSyncConfigAlwaysRendered(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/a_folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("a_folder").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		StoredFolderConfigs: []types.FolderConfig{
			{
				FolderPath: folderPath,
				EffectiveConfig: map[string]types.EffectiveValue{
					"scan_automatic": {Value: "auto", Source: "global"},
				},
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Scan Configuration and Filtering sections should always be rendered for folder settings
	assert.Contains(t, html, "Scan configuration")
	assert.Contains(t, html, "Filters and views")
}

func TestConfigHtmlRenderer_SecretsHiddenWhenFeatureFlagOff(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/a_folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("a_folder").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	// Feature flag NOT set — Snyk Secrets should be hidden
	resolver := testutil.DefaultConfigResolver(engine)
	fc := types.FolderConfig{
		FolderPath:     folderPath,
		ConfigResolver: resolver,
		EffectiveConfig: map[string]types.EffectiveValue{
			"snyk_secrets_enabled": {Value: true, Source: "ldx-sync"},
		},
	}

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		ActivateSnykSecrets: "true",
		StoredFolderConfigs: []types.FolderConfig{fc},
	}

	html := renderer.GetConfigHtml(settings)

	// Global Snyk Secrets checkbox should NOT appear when feature flag is off
	assert.NotContains(t, html, `name="snyk_secrets_enabled"`)
	// Per-folder Snyk Secrets override should NOT appear
	assert.NotContains(t, html, `data-setting="snyk_secrets_enabled"`)
}

func TestConfigHtmlRenderer_SecretsShownWhenFeatureFlagOn(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/a_folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("a_folder").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	// Set the feature flag ON for this folder
	resolver := testutil.DefaultConfigResolver(engine)
	fc := types.FolderConfig{
		FolderPath:     folderPath,
		ConfigResolver: resolver,
		EffectiveConfig: map[string]types.EffectiveValue{
			"snyk_secrets_enabled": {Value: true, Source: "ldx-sync"},
		},
	}
	// Write the feature flag into configuration
	ffKey := configresolver.FolderMetadataKey(string(types.PathKey(folderPath)), types.FeatureFlagPrefix+featureflag.SnykSecretsEnabled)
	engine.GetConfiguration().Set(ffKey, true)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		ActivateSnykSecrets: "true",
		StoredFolderConfigs: []types.FolderConfig{fc},
	}

	html := renderer.GetConfigHtml(settings)

	// Global Snyk Secrets checkbox SHOULD appear when feature flag is on
	assert.Contains(t, html, `name="snyk_secrets_enabled"`)
	// Per-folder Snyk Secrets override SHOULD appear
	assert.Contains(t, html, `data-setting="snyk_secrets_enabled"`)
}

func TestConfigHtmlRenderer_NoFoldersShowsDisabledTab(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{}).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		Token:    "test-token",
		Endpoint: "https://test.snyk.io",
		// No StoredFolderConfigs
	}

	html := renderer.GetConfigHtml(settings)

	// Should show disabled "No projects open" tab
	assert.Contains(t, html, "No projects open")
	assert.Contains(t, html, "nav-link disabled")
	assert.Contains(t, html, "Open a workspace to configure project-specific settings")
	// Should NOT show folder dropdown or folder tab elements
	assert.NotContains(t, html, `id="folderDropdown"`)
	assert.NotContains(t, html, `class="folder-tab-label"`)
	assert.NotContains(t, html, `id="folder-pane-`)
}

func TestConfigHtmlRenderer_SingleFolderShowsDirectTab(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/my-project")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("my-project").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		Token:    "test-token",
		Endpoint: "https://test.snyk.io",
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: folderPath},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Should show a direct tab with folder name and "- Project" label
	assert.Contains(t, html, "folder-tab-label")
	assert.Contains(t, html, "my-project")
	assert.Contains(t, html, "- Project")
	assert.Contains(t, html, "folder-pane-0")
	assert.Contains(t, html, string(folderPath))
	// Should NOT show folder dropdown or disabled tab
	assert.NotContains(t, html, `id="folderDropdown"`)
	assert.NotContains(t, html, "No folders open")
}

func TestConfigHtmlRenderer_FolderNameDiffersFromBasename(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath(filepath.Join("path", "to", "my-project"))
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("Custom Workspace Name").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: folderPath},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Should use the workspace folder Name(), not the path basename
	assert.Contains(t, html, "Custom Workspace Name")
	assert.NotContains(t, html, ">my-project<")
}

func TestConfigHtmlRenderer_EmptyNameFallsBackToBasename(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath(filepath.Join("path", "to", "my-project"))
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: folderPath},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// When Name() is empty, should fall back to filepath.Base of the path
	assert.Contains(t, html, "my-project")
}

func TestConfigHtmlRenderer_MultiFolderShowsDropdown(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder1 := mock_types.NewMockFolder(ctrl)
	mockFolder2 := mock_types.NewMockFolder(ctrl)

	folderPath1 := types.FilePath("/path/to/project-a")
	folderPath2 := types.FilePath("/path/to/project-b")
	mockFolder1.EXPECT().Path().Return(folderPath1).AnyTimes()
	mockFolder1.EXPECT().Name().Return("project-a").AnyTimes()
	mockFolder2.EXPECT().Path().Return(folderPath2).AnyTimes()
	mockFolder2.EXPECT().Name().Return("project-b").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder1, mockFolder2}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath1).Return(mockFolder1).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath2).Return(mockFolder2).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		Token:    "test-token",
		Endpoint: "https://test.snyk.io",
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: folderPath1},
			{FolderPath: folderPath2},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Should show the folder dropdown
	assert.Contains(t, html, "folder-dropdown")
	assert.Contains(t, html, "folderDropdownMenu")
	assert.Contains(t, html, "folder-dropdown-item")
	assert.Contains(t, html, "Projects")
	// Should have both folder panes and paths
	assert.Contains(t, html, "folder-pane-0")
	assert.Contains(t, html, "folder-pane-1")
	assert.Contains(t, html, string(folderPath1))
	assert.Contains(t, html, string(folderPath2))
	// Should NOT show single-folder direct tab or disabled tab
	assert.NotContains(t, html, `class="folder-tab-label"`)
	assert.NotContains(t, html, "No folders open")
	// Should have info boxes in both folder panes
	overrideCount := strings.Count(html, "These settings override the project defaults for this specific project.")
	assert.Equal(t, 2, overrideCount, "Info box should appear in both folder-specific tabs")
}

func TestConfigHtmlRenderer_FolderNamesAlignWithStoredFolderConfigs(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolderAlpha := mock_types.NewMockFolder(ctrl)
	mockFolderBeta := mock_types.NewMockFolder(ctrl)

	alphaPath := types.FilePath(filepath.Join("ws", "alpha"))
	betaPath := types.FilePath(filepath.Join("ws", "beta"))

	// Names deliberately differ from basenames to prove we use Name(), not the path
	mockFolderAlpha.EXPECT().Path().Return(alphaPath).AnyTimes()
	mockFolderAlpha.EXPECT().Name().Return("Alpha Workspace").AnyTimes()
	mockFolderBeta.EXPECT().Path().Return(betaPath).AnyTimes()
	mockFolderBeta.EXPECT().Name().Return("Beta Workspace").AnyTimes()

	// Workspace returns folders in alpha, beta order
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolderAlpha, mockFolderBeta}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(alphaPath).Return(mockFolderAlpha).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(betaPath).Return(mockFolderBeta).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	// StoredFolderConfigs in REVERSED order: beta first, alpha second
	settings := types.Settings{
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: betaPath},
			{FolderPath: alphaPath},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify names appear in StoredFolderConfigs order (beta, alpha), not Folders() order (alpha, beta)
	betaPos := strings.Index(html, "Beta Workspace")
	alphaPos := strings.Index(html, "Alpha Workspace")
	assert.Greater(t, betaPos, -1, "Beta Workspace should appear in HTML")
	assert.Greater(t, alphaPos, -1, "Alpha Workspace should appear in HTML")
	assert.Less(t, betaPos, alphaPos, "Beta Workspace should appear before Alpha Workspace (matching StoredFolderConfigs order)")

	// Verify basenames are NOT used as display names
	assert.NotContains(t, html, ">alpha<")
	assert.NotContains(t, html, ">beta<")
}

func TestConfigHtmlRenderer_LdxSyncConfigAlwaysRendered(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/a_folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("a_folder").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		StoredFolderConfigs: []types.FolderConfig{
			{
				FolderPath: folderPath,
				EffectiveConfig: map[string]types.EffectiveValue{
					"scan_automatic": {Value: "auto", Source: "global"},
				},
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Scan Configuration and Filtering sections should always be rendered for folder settings
	assert.Contains(t, html, "Scan Configuration")
	assert.Contains(t, html, "Filtering and Display")
}

func TestConfigHtmlRenderer_SecretsHiddenWhenFeatureFlagOff(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/a_folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("a_folder").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	// Feature flag NOT set — Snyk Secrets should be hidden
	resolver := testutil.DefaultConfigResolver(engine)
	fc := types.FolderConfig{
		FolderPath:     folderPath,
		ConfigResolver: resolver,
		EffectiveConfig: map[string]types.EffectiveValue{
			"snyk_secrets_enabled": {Value: true, Source: "ldx-sync"},
		},
	}

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		ActivateSnykSecrets: "true",
		StoredFolderConfigs: []types.FolderConfig{fc},
	}

	html := renderer.GetConfigHtml(settings)

	// Global Snyk Secrets checkbox should NOT appear when feature flag is off
	assert.NotContains(t, html, `name="activateSnykSecrets"`)
	// Per-folder Snyk Secrets override should NOT appear
	assert.NotContains(t, html, `data-setting="snyk_secrets_enabled"`)
}

func TestConfigHtmlRenderer_SecretsShownWhenFeatureFlagOn(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/a_folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("a_folder").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	// Set the feature flag ON for this folder
	resolver := testutil.DefaultConfigResolver(engine)
	fc := types.FolderConfig{
		FolderPath:     folderPath,
		ConfigResolver: resolver,
		EffectiveConfig: map[string]types.EffectiveValue{
			"snyk_secrets_enabled": {Value: true, Source: "ldx-sync"},
		},
	}
	// Write the feature flag into configuration
	ffKey := configresolver.FolderMetadataKey(string(types.PathKey(folderPath)), types.FeatureFlagPrefix+featureflag.SnykSecretsEnabled)
	engine.GetConfiguration().Set(ffKey, true)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		ActivateSnykSecrets: "true",
		StoredFolderConfigs: []types.FolderConfig{fc},
	}

	html := renderer.GetConfigHtml(settings)

	// Global Snyk Secrets checkbox SHOULD appear when feature flag is on
	assert.Contains(t, html, `name="activateSnykSecrets"`)
	// Per-folder Snyk Secrets override SHOULD appear
	assert.Contains(t, html, `data-setting="snyk_secrets_enabled"`)
}

func TestConfigHtmlRenderer_NoFoldersShowsDisabledTab(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{}).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		Token:    "test-token",
		Endpoint: "https://test.snyk.io",
		// No StoredFolderConfigs
	}

	html := renderer.GetConfigHtml(settings)

	// Should show disabled "No projects open" tab
	assert.Contains(t, html, "No projects open")
	assert.Contains(t, html, "nav-link disabled")
	assert.Contains(t, html, "Open a workspace to configure project-specific settings")
	// Should NOT show folder dropdown or folder tab elements
	assert.NotContains(t, html, `id="folderDropdown"`)
	assert.NotContains(t, html, `class="folder-tab-label"`)
	assert.NotContains(t, html, `id="folder-pane-`)
}

func TestConfigHtmlRenderer_SingleFolderShowsDirectTab(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/my-project")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("my-project").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		Token:    "test-token",
		Endpoint: "https://test.snyk.io",
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: folderPath},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Should show a direct tab with folder name and "- Project" label
	assert.Contains(t, html, "folder-tab-label")
	assert.Contains(t, html, "my-project")
	assert.Contains(t, html, "- Project")
	assert.Contains(t, html, "folder-pane-0")
	assert.Contains(t, html, string(folderPath))
	// Should NOT show folder dropdown or disabled tab
	assert.NotContains(t, html, `id="folderDropdown"`)
	assert.NotContains(t, html, "No folders open")
}

func TestConfigHtmlRenderer_FolderNameDiffersFromBasename(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath(filepath.Join("path", "to", "my-project"))
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("Custom Workspace Name").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: folderPath},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Should use the workspace folder Name(), not the path basename
	assert.Contains(t, html, "Custom Workspace Name")
	assert.NotContains(t, html, ">my-project<")
}

func TestConfigHtmlRenderer_EmptyNameFallsBackToBasename(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath(filepath.Join("path", "to", "my-project"))
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: folderPath},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// When Name() is empty, should fall back to filepath.Base of the path
	assert.Contains(t, html, "my-project")
}

func TestConfigHtmlRenderer_MultiFolderShowsDropdown(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder1 := mock_types.NewMockFolder(ctrl)
	mockFolder2 := mock_types.NewMockFolder(ctrl)

	folderPath1 := types.FilePath("/path/to/project-a")
	folderPath2 := types.FilePath("/path/to/project-b")
	mockFolder1.EXPECT().Path().Return(folderPath1).AnyTimes()
	mockFolder1.EXPECT().Name().Return("project-a").AnyTimes()
	mockFolder2.EXPECT().Path().Return(folderPath2).AnyTimes()
	mockFolder2.EXPECT().Name().Return("project-b").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder1, mockFolder2}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath1).Return(mockFolder1).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath2).Return(mockFolder2).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		Token:    "test-token",
		Endpoint: "https://test.snyk.io",
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: folderPath1},
			{FolderPath: folderPath2},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Should show the folder dropdown
	assert.Contains(t, html, "folder-dropdown")
	assert.Contains(t, html, "folderDropdownMenu")
	assert.Contains(t, html, "folder-dropdown-item")
	assert.Contains(t, html, "Projects")
	// Should have both folder panes and paths
	assert.Contains(t, html, "folder-pane-0")
	assert.Contains(t, html, "folder-pane-1")
	assert.Contains(t, html, string(folderPath1))
	assert.Contains(t, html, string(folderPath2))
	// Should NOT show single-folder direct tab or disabled tab
	assert.NotContains(t, html, `class="folder-tab-label"`)
	assert.NotContains(t, html, "No folders open")
}

func TestConfigHtmlRenderer_FolderNamesAlignWithStoredFolderConfigs(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolderAlpha := mock_types.NewMockFolder(ctrl)
	mockFolderBeta := mock_types.NewMockFolder(ctrl)

	alphaPath := types.FilePath(filepath.Join("ws", "alpha"))
	betaPath := types.FilePath(filepath.Join("ws", "beta"))

	// Names deliberately differ from basenames to prove we use Name(), not the path
	mockFolderAlpha.EXPECT().Path().Return(alphaPath).AnyTimes()
	mockFolderAlpha.EXPECT().Name().Return("Alpha Workspace").AnyTimes()
	mockFolderBeta.EXPECT().Path().Return(betaPath).AnyTimes()
	mockFolderBeta.EXPECT().Name().Return("Beta Workspace").AnyTimes()

	// Workspace returns folders in alpha, beta order
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolderAlpha, mockFolderBeta}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(alphaPath).Return(mockFolderAlpha).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(betaPath).Return(mockFolderBeta).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	// StoredFolderConfigs in REVERSED order: beta first, alpha second
	settings := types.Settings{
		StoredFolderConfigs: []types.FolderConfig{
			{FolderPath: betaPath},
			{FolderPath: alphaPath},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify names appear in StoredFolderConfigs order (beta, alpha), not Folders() order (alpha, beta)
	betaPos := strings.Index(html, "Beta Workspace")
	alphaPos := strings.Index(html, "Alpha Workspace")
	assert.Greater(t, betaPos, -1, "Beta Workspace should appear in HTML")
	assert.Greater(t, alphaPos, -1, "Alpha Workspace should appear in HTML")
	assert.Less(t, betaPos, alphaPos, "Beta Workspace should appear before Alpha Workspace (matching StoredFolderConfigs order)")

	// Verify basenames are NOT used as display names
	assert.NotContains(t, html, ">alpha<")
	assert.NotContains(t, html, ">beta<")
}

func TestConfigHtmlRenderer_EclipseShowsProjectSettings(t *testing.T) {
	engine := testutil.UnitTest(t)

	// Set up mock workspace with a folder
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/project")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("project").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)
	assert.NotNil(t, renderer)

	settings := types.Settings{
		IntegrationName:  "ECLIPSE",
		Token:            "test-token",
		Endpoint:         "https://test.snyk.io",
		ActivateSnykCode: "true",
		StoredFolderConfigs: []types.FolderConfig{
			{
				FolderPath: folderPath,
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify Eclipse shows "Project" tab label instead of "Folder"
	assert.Contains(t, html, "project")
	assert.Contains(t, html, "- Project")
}

func TestTmplSourceIndicator(t *testing.T) {
	tests := []struct {
		name            string
		effectiveConfig map[string]types.EffectiveValue
		settingName     string
		expectedHTML    string
		shouldContain   []string
	}{
		{
			name: "ldx-sync-locked returns locked indicator",
			effectiveConfig: map[string]types.EffectiveValue{
				"test_setting": {Value: "true", Source: "ldx-sync-locked"},
			},
			settingName:  "test_setting",
			expectedHTML: `<span class="source-indicator" data-toggle="tooltip" title="Locked due to organization settings">🏢🔒</span>`,
			shouldContain: []string{
				`class="source-indicator"`,
				`data-toggle="tooltip"`,
				`title="Locked due to organization settings"`,
				"🏢🔒",
			},
		},
		{
			name: "ldx-sync returns organization indicator",
			effectiveConfig: map[string]types.EffectiveValue{
				"test_setting": {Value: "true", Source: "ldx-sync"},
			},
			settingName:  "test_setting",
			expectedHTML: `<span class="source-indicator" data-toggle="tooltip" title="Set by your organization settings">🏢</span>`,
			shouldContain: []string{
				`class="source-indicator"`,
				`data-toggle="tooltip"`,
				`title="Set by your organization settings"`,
				"🏢",
			},
		},
		{
			name: "user-override returns empty (indicated by CSS border)",
			effectiveConfig: map[string]types.EffectiveValue{
				"test_setting": {Value: "true", Source: "user-override"},
			},
			settingName:   "test_setting",
			expectedHTML:  "",
			shouldContain: []string{},
		},
		{
			name: "global source returns empty",
			effectiveConfig: map[string]types.EffectiveValue{
				"test_setting": {Value: "true", Source: "global"},
			},
			settingName:   "test_setting",
			expectedHTML:  "",
			shouldContain: []string{},
		},
		{
			name: "default source returns empty",
			effectiveConfig: map[string]types.EffectiveValue{
				"test_setting": {Value: "true", Source: "default"},
			},
			settingName:   "test_setting",
			expectedHTML:  "",
			shouldContain: []string{},
		},
		{
			name:            "nil config returns empty",
			effectiveConfig: nil,
			settingName:     "test_setting",
			expectedHTML:    "",
			shouldContain:   []string{},
		},
		{
			name:            "missing setting returns empty",
			effectiveConfig: map[string]types.EffectiveValue{},
			settingName:     "nonexistent_setting",
			expectedHTML:    "",
			shouldContain:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tmplSourceIndicator(tt.effectiveConfig, tt.settingName)

			// Verify return type is template.HTML
			assert.Equal(t, string(template.HTML(tt.expectedHTML)), string(result))

			// Verify all expected substrings are present
			resultStr := string(result)
			for _, substr := range tt.shouldContain {
				assert.Contains(t, resultStr, substr, "Expected substring not found in result")
			}
		})
	}
}

func TestConfigHtmlRenderer_SourceIndicatorsInOutput(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/a_folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockFolder.EXPECT().Name().Return("a_folder").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(folderPath).Return(mockFolder).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)

	settings := types.Settings{
		StoredFolderConfigs: []types.FolderConfig{
			{
				FolderPath: folderPath,
				EffectiveConfig: map[string]types.EffectiveValue{
					"snyk_oss_enabled":     {Value: true, Source: "ldx-sync-locked"},
					"snyk_code_enabled":    {Value: true, Source: "ldx-sync"},
					"snyk_iac_enabled":     {Value: true, Source: "user-override"},
					"snyk_secrets_enabled": {Value: true, Source: "global"},
				},
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify locked indicator (🏢🔒) appears for ldx-sync-locked
	assert.Contains(t, html, "🏢🔒")
	assert.Contains(t, html, `title="Locked due to organization settings"`)

	// Verify organization indicator (🏢) appears for ldx-sync
	// Count occurrences to ensure we have at least one for the organization setting
	orgIndicatorCount := strings.Count(html, `title="Set by your organization settings"`)
	assert.Greater(t, orgIndicatorCount, 0, "Organization indicator should appear in HTML")

	// Verify HTML is not empty (basic sanity check)
	assert.NotEmpty(t, html, "HTML output should not be empty")
}

func TestComputeProjectDefaultScopes(t *testing.T) {
	engine := testutil.UnitTest(t)

	result := computeProjectDefaultScopes(engine)

	// Should return a map with entries for all org-scope settings
	assert.Equal(t, 14, len(result), "Should have entries for all 14 org-scope settings")

	// Verify all expected settings are present
	expectedSettings := []string{
		types.SettingSeverityFilterCritical,
		types.SettingSeverityFilterHigh,
		types.SettingSeverityFilterMedium,
		types.SettingSeverityFilterLow,
		types.SettingIssueViewOpenIssues,
		types.SettingIssueViewIgnoredIssues,
		types.SettingScanAutomatic,
		types.SettingScanNetNew,
		types.SettingSnykCodeEnabled,
		types.SettingSnykOssEnabled,
		types.SettingSnykIacEnabled,
		types.SettingSnykSecretsEnabled,
		types.SettingRiskScoreThreshold,
		types.SettingOrganization,
	}

	for _, setting := range expectedSettings {
		assert.Contains(t, result, setting, "Result should contain setting: %s", setting)
		// Source should be a non-empty string
		assert.NotEmpty(t, result[setting], "Source for %s should not be empty", setting)
	}
}
