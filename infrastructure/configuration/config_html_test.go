package configuration

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestConfigHtmlRenderer_GetConfigHtml(t *testing.T) {
	c := config.CurrentConfig()
	renderer, err := NewConfigHtmlRenderer(c)
	assert.NoError(t, err)
	assert.NotNil(t, renderer)

	settings := types.Settings{
		Token:                    "test-token",
		Endpoint:                 "https://test.snyk.io",
		Organization:             "test-org",
		Insecure:                 "true",
		ActivateSnykOpenSource:   "true",
		ActivateSnykCodeSecurity: "false",
		AuthenticationMethod:     "oauth",
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath: "/path/to/folder",
				BaseBranch: "main",
			},
		},
	}

	html := renderer.GetConfigHtml(settings)

	// Verify visible fields in simplified UI
	assert.Contains(t, html, "test-token")
	assert.Contains(t, html, "https://test.snyk.io")
	assert.Contains(t, html, "/path/to/folder")
	assert.Contains(t, html, "checked") // Insecure checkbox
	assert.Contains(t, html, "window.__ideSaveConfig__")
	assert.Contains(t, html, "window.__ideLogin__")
	assert.Contains(t, html, "window.__ideLogout__")
	assert.Contains(t, html, "Activate Snyk Code")
	assert.Contains(t, html, "Authentication Method")
	assert.Contains(t, html, "oauth")
	assert.Contains(t, html, "Scan Configuration") // Section header
	assert.Contains(t, html, "Filter and Display Settings") // Section header
	assert.Contains(t, html, "Folder Settings") // Section header
}
