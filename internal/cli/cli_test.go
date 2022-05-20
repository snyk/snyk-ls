package cli

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestExpandParametersFromConfig(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetOrganization("test-org")
	settings := config.CliSettings{
		Insecure:             true,
		Endpoint:             "test-endpoint",
		AdditionalParameters: []string{"--all-projects", "-d"},
	}
	config.CurrentConfig().SetCliSettings(settings)
	var cmd []string
	cmd = ExpandParametersFromConfig(cmd)
	assert.Contains(t, cmd, "--insecure")
	assert.Contains(t, cmd, "--all-projects")
	assert.Contains(t, cmd, "-d")
	assert.Equal(t, config.CurrentConfig().GetOrganization(), os.Getenv(config.Organization))
}
