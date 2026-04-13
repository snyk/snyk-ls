package configuration

import (
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
		"activateSnykOpenSource",
		"activateSnykCode",
		"activateSnykIac",
		"scanningMode",
		"filterSeverity_critical",
		"filterSeverity_high",
		"filterSeverity_medium",
		"filterSeverity_low",
		"issueViewOptions_openIssues",
		"issueViewOptions_ignoredIssues",
		"riskScoreThreshold",
		"enableDeltaFindings",
		"authenticationMethod",
		"endpoint",
		"insecure",
		"token",
		"cliPath",
		"manageBinariesAutomatically",
		"cliReleaseChannel",
		"cliBaseDownloadURL",
		"trustedFolders",
	}

	for _, key := range expectedSettingKeys {
		assert.Contains(t, html, `data-setting-key="`+key+`"`)
	}
	assert.Contains(t, html, "window.__saveIdeConfig__")
	assert.Contains(t, html, "window.getAndSaveIdeConfig")
	assert.Contains(t, html, "window.__ideExecuteCommand__")
	assert.Contains(t, html, "Snyk Code")
	assert.Contains(t, html, "Authentication method")
	assert.Contains(t, html, "oauth")
	assert.Contains(t, html, "Scan configuration") // Section header
	assert.Contains(t, html, "Filters and views")  // Section header
	assert.Contains(t, html, "Trust settings")     // Section header
	assert.Contains(t, html, "CLI configuration")  // Section header
	assert.Contains(t, html, "- Folder")           // Folder tab label
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

	// Should show disabled "No folders open" tab
	assert.Contains(t, html, "No folders open")
	assert.Contains(t, html, "nav-link disabled")
	assert.Contains(t, html, "Open a workspace to configure folder-specific settings")
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

	// Should show a direct tab with folder name and "- Folder" label
	assert.Contains(t, html, "folder-tab-label")
	assert.Contains(t, html, "my-project")
	assert.Contains(t, html, "- Folder")
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
	assert.Contains(t, html, "Folders")
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
