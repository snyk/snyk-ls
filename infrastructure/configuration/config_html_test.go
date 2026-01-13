package configuration

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestConfigHtmlRenderer_GetConfigHtml(t *testing.T) {
	c := config.CurrentConfig()

	// Set up mock workspace with a folder
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()

	c.SetWorkspace(mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(c)
	assert.NoError(t, err)
	assert.NotNil(t, renderer)

	settings := types.Settings{
		Token:                  "test-token",
		Endpoint:               "https://test.snyk.io",
		Organization:           "test-org",
		Insecure:               "true",
		ActivateSnykOpenSource: "true",
		ActivateSnykCode:       "true",
		AuthenticationMethod:   "oauth",
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath: "/path/to/folder",
				BaseBranch: "main",
				ScanCommandConfig: map[product.Product]types.ScanCommandConfig{
					product.ProductOpenSource: {
						PreScanCommand: "npm install",
					},
				},
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify visible fields in simplified UI
	assert.Contains(t, html, "test-token")
	assert.Contains(t, html, "https://test.snyk.io")
	assert.Contains(t, html, "/path/to/folder")
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
	assert.Contains(t, html, "window.__ideLogin__")
	assert.Contains(t, html, "window.__ideLogout__")
	assert.Contains(t, html, "Snyk Code")
	assert.Contains(t, html, "Authentication Method")
	assert.Contains(t, html, "oauth")
	assert.Contains(t, html, "Scan Configuration")    // Section header
	assert.Contains(t, html, "Filtering and Display") // Section header
	assert.Contains(t, html, "Folder Settings")       // Section header
	assert.Contains(t, html, "CLI Configuration")     // Section header
}

func TestConfigHtmlRenderer_FiltersFolderConfigsNotInWorkspace(t *testing.T) {
	c := config.CurrentConfig()

	// Set up mock workspace with only one folder
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	// Workspace only has /workspace/folder1
	workspaceFolderPath := types.FilePath("/workspace/folder1")
	mockFolder.EXPECT().Path().Return(workspaceFolderPath).AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()

	c.SetWorkspace(mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(c)
	assert.NoError(t, err)
	assert.NotNil(t, renderer)

	// Settings include two folders: one in workspace, one external
	settings := types.Settings{
		Token:                  "test-token",
		Endpoint:               "https://test.snyk.io",
		AuthenticationMethod:   "token",
		ActivateSnykOpenSource: "true",
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:        workspaceFolderPath,
				BaseBranch:        "main",
				ScanCommandConfig: map[product.Product]types.ScanCommandConfig{}, // Empty map to test edge case
			},
			{
				FolderPath: "/external/folder2",
				BaseBranch: "develop",
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify workspace folder is included
	assert.Contains(t, html, "/workspace/folder1")

	// Verify external folder is NOT included
	assert.NotContains(t, html, "/external/folder2")
}

func TestConfigHtmlRenderer_NoWorkspaceFiltersAllFolders(t *testing.T) {
	c := config.CurrentConfig()
	// No workspace set (nil)

	renderer, err := NewConfigHtmlRenderer(c)
	assert.NoError(t, err)
	assert.NotNil(t, renderer)

	settings := types.Settings{
		Token:                  "test-token",
		Endpoint:               "https://test.snyk.io",
		AuthenticationMethod:   "token",
		ActivateSnykOpenSource: "true",
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath: "/some/folder",
				BaseBranch: "main",
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify folder is NOT included when no workspace is set
	assert.NotContains(t, html, "/some/folder")

	// Verify message about no folders configured is shown
	assert.Contains(t, html, "No folder")
}

func TestConfigHtmlRenderer_EclipseShowsProjectSettings(t *testing.T) {
	c := config.CurrentConfig()

	// Set up mock workspace with a folder
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)

	folderPath := types.FilePath("/path/to/project")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()

	c.SetWorkspace(mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(c)
	assert.NoError(t, err)
	assert.NotNil(t, renderer)

	settings := types.Settings{
		IntegrationName:  "ECLIPSE",
		Token:            "test-token",
		Endpoint:         "https://test.snyk.io",
		ActivateSnykCode: "true",
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath: folderPath,
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify Eclipse shows "Project Settings" instead of "Folder Settings"
	assert.Contains(t, html, "Project Settings")
}
