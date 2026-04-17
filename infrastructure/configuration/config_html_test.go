package configuration

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
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

	folderPath := types.FilePath("/path/to/folder")
	mockFolder.EXPECT().Path().Return(folderPath).AnyTimes()
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()

	config.SetWorkspace(engine.GetConfiguration(), mockWorkspace)

	renderer, err := NewConfigHtmlRenderer(engine)
	assert.NoError(t, err)
	assert.NotNil(t, renderer)

	settings := map[string]any{
		types.SettingToken:                  "test-token",
		types.SettingApiEndpoint:            "https://test.snyk.io",
		types.SettingOrganization:           "test-org",
		types.SettingProxyInsecure:          true,
		types.SettingSnykOssEnabled:         true,
		types.SettingSnykCodeEnabled:        true,
		types.SettingAuthenticationMethod:   "oauth",
		types.SettingScanAutomatic:          true,
		types.SettingScanNetNew:             false,
		types.SettingSeverityFilterCritical: true,
		types.SettingSeverityFilterHigh:     true,
		types.SettingSeverityFilterMedium:   true,
		types.SettingSeverityFilterLow:      true,
		types.SettingIssueViewOpenIssues:    true,
		types.SettingIssueViewIgnoredIssues: false,
		types.SettingCliPath:                "",
		types.SettingAutomaticDownload:      true,
		types.SettingBinaryBaseUrl:          "",
		types.SettingCliReleaseChannel:      "",
		types.SettingTrustedFolders:         []string{},
		types.SettingRiskScoreThreshold:     0,
		"integration_name":                  "",
	}
	folderConfigs := []types.FolderConfig{
		{FolderPath: "/path/to/folder"},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

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

	settings := map[string]any{
		types.SettingToken:                  "test-token",
		types.SettingApiEndpoint:            "https://test.snyk.io",
		types.SettingSnykCodeEnabled:        true,
		types.SettingSnykOssEnabled:         false,
		types.SettingSnykIacEnabled:         false,
		types.SettingSnykSecretsEnabled:     false,
		types.SettingScanAutomatic:          true,
		types.SettingScanNetNew:             false,
		types.SettingOrganization:           "",
		types.SettingSeverityFilterCritical: true,
		types.SettingSeverityFilterHigh:     true,
		types.SettingSeverityFilterMedium:   true,
		types.SettingSeverityFilterLow:      true,
		types.SettingIssueViewOpenIssues:    true,
		types.SettingIssueViewIgnoredIssues: false,
		types.SettingRiskScoreThreshold:     0,
		types.SettingProxyInsecure:          false,
		types.SettingAuthenticationMethod:   "",
		types.SettingCliPath:                "",
		types.SettingAutomaticDownload:      false,
		types.SettingBinaryBaseUrl:          "",
		types.SettingCliReleaseChannel:      "",
		types.SettingTrustedFolders:         []string{},
		"integration_name":                  "ECLIPSE",
	}
	folderConfigs := []types.FolderConfig{
		{FolderPath: folderPath},
	}

	html := renderer.GetConfigHtml(settings, folderConfigs)

	// Verify Eclipse shows "Project Settings" instead of "Folder Settings"
	assert.Contains(t, html, "Project Settings")
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
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder}).AnyTimes()
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

	html := renderer.GetConfigHtmlWithOptions(settings, folderConfigs, ConfigHtmlOptions{
		EnableLdxSyncConfig: true,
	})
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
