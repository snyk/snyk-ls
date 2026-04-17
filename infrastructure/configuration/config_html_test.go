package configuration

import (
	"fmt"
	"html/template"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
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

	settings := map[string]any{
		types.SettingToken:                "test-token",
		types.SettingApiEndpoint:          "https://test.snyk.io",
		types.SettingOrganization:         "test-org",
		types.SettingProxyInsecure:        true,
		types.SettingSnykOssEnabled:       true,
		types.SettingSnykCodeEnabled:      true,
		types.SettingAuthenticationMethod: "oauth",
	}
	folderConfigs := []types.FolderConfig{
		{FolderPath: folderPath},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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
		"severity_filter_critical",
		"severity_filter_high",
		"severity_filter_medium",
		"severity_filter_low",
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

	settings := map[string]any{}
	folderConfigs := []types.FolderConfig{
		{
			FolderPath: folderPath,
			EffectiveConfig: map[string]types.EffectiveValue{
				"scan_automatic": {Value: "auto", Source: "global"},
			},
		},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

	settings := map[string]any{
		types.SettingSnykSecretsEnabled: true,
	}
	folderConfigs := []types.FolderConfig{fc}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

	settings := map[string]any{
		types.SettingSnykSecretsEnabled: true,
	}
	folderConfigs := []types.FolderConfig{fc}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

	settings := map[string]any{
		types.SettingToken:       "test-token",
		types.SettingApiEndpoint: "https://test.snyk.io",
	}
	// No folder configs

	html := renderer.GetConfigHtml(settings, nil)

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

	settings := map[string]any{
		types.SettingToken:       "test-token",
		types.SettingApiEndpoint: "https://test.snyk.io",
	}
	folderConfigs := []types.FolderConfig{
		{FolderPath: folderPath},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

	settings := map[string]any{}
	folderConfigs := []types.FolderConfig{
		{FolderPath: folderPath},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

	settings := map[string]any{}
	folderConfigs := []types.FolderConfig{
		{FolderPath: folderPath},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

	settings := map[string]any{
		types.SettingToken:       "test-token",
		types.SettingApiEndpoint: "https://test.snyk.io",
	}
	folderConfigs := []types.FolderConfig{
		{FolderPath: folderPath1},
		{FolderPath: folderPath2},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

	// folderConfigs in REVERSED order: beta first, alpha second
	settings := map[string]any{}
	folderConfigs := []types.FolderConfig{
		{FolderPath: betaPath},
		{FolderPath: alphaPath},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

	// Verify names appear in folderConfigs order (beta, alpha), not Folders() order (alpha, beta)
	betaPos := strings.Index(html, "Beta Workspace")
	alphaPos := strings.Index(html, "Alpha Workspace")
	assert.Greater(t, betaPos, -1, "Beta Workspace should appear in HTML")
	assert.Greater(t, alphaPos, -1, "Alpha Workspace should appear in HTML")
	assert.Less(t, betaPos, alphaPos, "Beta Workspace should appear before Alpha Workspace (matching folderConfigs order)")

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

	settings := map[string]any{
		"integration_name":           "ECLIPSE",
		types.SettingToken:           "test-token",
		types.SettingApiEndpoint:     "https://test.snyk.io",
		types.SettingSnykCodeEnabled: true,
	}
	folderConfigs := []types.FolderConfig{
		{FolderPath: folderPath},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

	settings := map[string]any{}
	folderConfigs := []types.FolderConfig{
		{
			FolderPath: folderPath,
			EffectiveConfig: map[string]types.EffectiveValue{
				"snyk_oss_enabled":     {Value: true, Source: "ldx-sync-locked"},
				"snyk_code_enabled":    {Value: true, Source: "ldx-sync"},
				"snyk_iac_enabled":     {Value: true, Source: "user-override"},
				"snyk_secrets_enabled": {Value: true, Source: "global"},
			},
		},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

// TestConfigHtml_FormFieldNamesMatchRegisteredSettings enforces that every HTML form
// field name= attribute corresponds to a registered pflag setting constant. This prevents
// typos and mismatches between the HTML form and the LS wire protocol.
func TestConfigHtml_FormFieldNamesMatchRegisteredSettings(t *testing.T) {
	engine := testutil.UnitTest(t)

	// 1. Get all registered pflag flag names
	fs := pflag.NewFlagSet("enforcement-test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)

	registeredFlags := make(map[string]bool)
	fs.VisitAll(func(f *pflag.Flag) {
		registeredFlags[f.Name] = true
	})

	// 2. Render HTML with all sections enabled
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)
	mockFolder.EXPECT().Path().Return(types.FilePath("/path/to/folder")).AnyTimes()
	mockFolder.EXPECT().Name().Return("folder").AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	mockWorkspace.EXPECT().GetFolderContaining(types.FilePath("/path/to/folder")).Return(mockFolder).AnyTimes()
	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	require.NoError(t, err)

	settings := map[string]any{
		types.SettingSnykOssEnabled:         true,
		types.SettingSnykCodeEnabled:        true,
		types.SettingSnykIacEnabled:         true,
		types.SettingSnykSecretsEnabled:     true,
		types.SettingScanAutomatic:          true,
		types.SettingScanNetNew:             false,
		types.SettingOrganization:           "test-org",
		types.SettingSeverityFilterCritical: true,
		types.SettingSeverityFilterHigh:     true,
		types.SettingSeverityFilterMedium:   true,
		types.SettingSeverityFilterLow:      true,
		types.SettingIssueViewOpenIssues:    true,
		types.SettingIssueViewIgnoredIssues: false,
		types.SettingRiskScoreThreshold:     0,
		types.SettingApiEndpoint:            "https://api.snyk.io",
		types.SettingProxyInsecure:          false,
		types.SettingAuthenticationMethod:   "oauth",
		types.SettingToken:                  "test-token",
		types.SettingCliPath:                "/usr/bin/snyk",
		types.SettingAutomaticDownload:      true,
		types.SettingCliReleaseChannel:      "",
		types.SettingBinaryBaseUrl:          "",
		types.SettingTrustedFolders:         []string{"/path/a"},
		"integration_name":                  "VS_CODE",
	}
	folderConfigs := []types.FolderConfig{
		{
			FolderPath: "/path/to/folder",
			EffectiveConfig: map[string]types.EffectiveValue{
				types.SettingScanAutomatic:          {Value: true, Source: "global"},
				types.SettingScanNetNew:             {Value: false, Source: "global"},
				types.SettingSeverityFilterCritical: {Value: true, Source: "global"},
				types.SettingSeverityFilterHigh:     {Value: true, Source: "global"},
				types.SettingSeverityFilterMedium:   {Value: true, Source: "global"},
				types.SettingSeverityFilterLow:      {Value: true, Source: "global"},
				types.SettingSnykOssEnabled:         {Value: true, Source: "global"},
				types.SettingSnykCodeEnabled:        {Value: true, Source: "global"},
				types.SettingSnykIacEnabled:         {Value: true, Source: "global"},
				types.SettingSnykSecretsEnabled:     {Value: true, Source: "global"},
				types.SettingIssueViewOpenIssues:    {Value: true, Source: "global"},
				types.SettingIssueViewIgnoredIssues: {Value: false, Source: "global"},
				types.SettingRiskScoreThreshold:     {Value: 0, Source: "global"},
			},
		},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)
	require.NotEmpty(t, html)

	// 3. Parse all name="..." attributes
	nameRegex := regexp.MustCompile(`name="([^"]+)"`)
	matches := nameRegex.FindAllStringSubmatch(html, -1)

	// UI-only helpers and non-form-element name= attributes
	allowedNonPflag := map[string]bool{
		"cli_release_channel_custom": true,
		"viewport":                   true, // <meta name="viewport"> — not a form field
	}

	trustedFolderPattern := regexp.MustCompile(`^trustedFolder_\d+$`)
	folderFieldPattern := regexp.MustCompile(`^folder_\d+_(.+)$`)

	// Known folder-level fields that are not pflag settings
	folderNonPflagFields := map[string]bool{
		"folderPath": true,
	}

	var violations []string
	for _, match := range matches {
		fieldName := match[1]

		if allowedNonPflag[fieldName] {
			continue
		}
		if trustedFolderPattern.MatchString(fieldName) {
			continue
		}

		if folderFieldPattern.MatchString(fieldName) {
			submatches := folderFieldPattern.FindStringSubmatch(fieldName)
			field := submatches[1]

			// scanConfig fields are part of scan_command_config
			if strings.HasPrefix(field, "scanConfig_") {
				continue
			}

			if registeredFlags[field] || folderNonPflagFields[field] {
				continue
			}

			violations = append(violations, fmt.Sprintf(
				"folder field %q (from name=%q) is not a registered pflag setting",
				field, fieldName))
			continue
		}

		// Global field: must be a registered pflag
		if !registeredFlags[fieldName] {
			violations = append(violations, fmt.Sprintf(
				"global field name=%q is not a registered pflag setting", fieldName))
		}
	}

	if len(violations) > 0 {
		t.Errorf("Found %d HTML form field name(s) that don't match registered pflag settings:\n%s",
			len(violations), strings.Join(violations, "\n"))
	}
}
