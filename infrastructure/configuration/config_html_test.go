package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
	"github.com/snyk/snyk-ls/internal/util"
)

// TestGenerateJSTestFixture renders config.html with representative settings and writes the result
// to template/js-tests/fixture.html so that JS tests load the real rendered HTML instead of a
// hand-crafted approximation. Run via: GENERATE_JS_FIXTURE=true go test -run TestGenerateJSTestFixture
func TestGenerateJSTestFixture(t *testing.T) {
	if os.Getenv("GENERATE_JS_FIXTURE") != "true" {
		t.Skip("set GENERATE_JS_FIXTURE=true to regenerate the JS test fixture")
	}

	c := config.CurrentConfig()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockFolder := mock_types.NewMockFolder(ctrl)
	mockFolder.EXPECT().Path().Return(types.FilePath("/path/to/folder")).AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
	c.SetWorkspace(mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(c)
	require.NoError(t, err)

	html := renderer.GetConfigHtml(types.Settings{
		Token:                "test-token",
		Endpoint:             "https://api.snyk.io",
		AuthenticationMethod: "oauth",
		Insecure:             "false",
		StoredFolderConfigs:  []types.FolderConfig{{FolderPath: "/path/to/folder"}},
	})

	fixturePath := filepath.Join("template", "js-tests", "fixture.html")
	require.NoError(t, os.WriteFile(fixturePath, []byte(html), 0600))
	t.Logf("wrote JS test fixture to %s", fixturePath)
}

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
		Organization:           util.Ptr("test-org"),
		Insecure:               "true",
		ActivateSnykOpenSource: "true",
		ActivateSnykCode:       "true",
		AuthenticationMethod:   "oauth",
		StoredFolderConfigs: []types.FolderConfig{
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
	assert.Contains(t, html, "window.__ideExecuteCommand__")
	assert.Contains(t, html, "snyk.login")
	assert.Contains(t, html, "snyk.logout")
	assert.Contains(t, html, "ConfigApp.authFieldMonitor")
	assert.Contains(t, html, "Snyk Code")
	assert.Contains(t, html, "Authentication Method")
	assert.Contains(t, html, "oauth")
	assert.Contains(t, html, "Scan Configuration")    // Section header
	assert.Contains(t, html, "Filtering and Display") // Section header
	assert.Contains(t, html, "Folder Settings")       // Section header
	assert.Contains(t, html, "CLI Configuration")     // Section header
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
		StoredFolderConfigs: []types.FolderConfig{
			{
				FolderPath: folderPath,
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify Eclipse shows "Project Settings" instead of "Folder Settings"
	assert.Contains(t, html, "Project Settings")
}
