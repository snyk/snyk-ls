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

	assert.Contains(t, html, "test-token")
	assert.Contains(t, html, "https://test.snyk.io")
	assert.Contains(t, html, "test-org")
	assert.Contains(t, html, "/path/to/folder")
	assert.Contains(t, html, "main")
	assert.Contains(t, html, "checked") // Insecure checkbox
	assert.Contains(t, html, "${ideSaveConfig}")
	assert.Contains(t, html, "${ideLogin}")
	assert.Contains(t, html, "Activate Snyk Code Security")
	assert.Contains(t, html, "Authentication Method")
	assert.Contains(t, html, "oauth")
}
