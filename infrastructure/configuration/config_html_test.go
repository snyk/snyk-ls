package configuration

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
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

	folderPath := types.FilePath("/path/to/folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()

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
			{FolderPath: "/path/to/folder"},
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
	assert.Contains(t, html, "Authentication Method")
	assert.Contains(t, html, "oauth")
	assert.Contains(t, html, "Scan Configuration") // Section header
	assert.Contains(t, html, "Filters and Views")  // Section header
	assert.Contains(t, html, "Trust Settings")     // Section header
	assert.Contains(t, html, "CLI Configuration")  // Section header
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
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()

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

	// Verify Eclipse shows "Project Settings" instead of "Folder Settings"
	assert.Contains(t, html, "Project Settings")
}
