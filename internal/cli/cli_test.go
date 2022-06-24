package cli

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_ExpandParametersFromConfig(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetOrganization("test-org")
	settings := config.CliSettings{
		Insecure:             true,
		Endpoint:             "test-endpoint",
		AdditionalParameters: []string{"--all-projects", "-d"},
	}
	config.CurrentConfig().SetCliSettings(settings)
	var cmd = []string{"a", "b"}
	cmd = SnykCli{}.ExpandParametersFromConfig(cmd)
	assert.Contains(t, cmd, "--insecure")
	assert.Contains(t, cmd, "--all-projects")
	assert.Contains(t, cmd, "-d")
}

func Test_ExpandParametersFromConfigNoAllProjectsForIac(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetOrganization("test-org")
	settings := config.CliSettings{
		Insecure:             true,
		Endpoint:             "test-endpoint",
		AdditionalParameters: []string{"--all-projects", "-d"},
	}
	config.CurrentConfig().SetCliSettings(settings)
	var cmd = []string{"a", "iac"}
	cmd = SnykCli{}.ExpandParametersFromConfig(cmd)
	assert.Contains(t, cmd, "--insecure")
	assert.NotContains(t, cmd, "--all-projects")
	assert.Contains(t, cmd, "-d")
}

func TestAddConfigToEnv(t *testing.T) {
	testutil.UnitTest(t)
	cli := SnykCli{}
	config.CurrentConfig().SetOrganization("testOrg")
	config.CurrentConfig().SetCliSettings(config.CliSettings{Endpoint: "testEndpoint"})

	updatedEnv := cli.addConfigValuesToEnv([]string{})

	assert.Contains(t, updatedEnv, "SNYK_CFG_ORG="+config.CurrentConfig().GetOrganization())
	assert.Contains(t, updatedEnv, "SNYK_API="+config.CurrentConfig().CliSettings().Endpoint)
	assert.Contains(t, updatedEnv, "SNYK_TOKEN="+config.CurrentConfig().Token())
}

func TestGetCommand_AddsToEnvironmentAndSetsDir(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetOrganization("TestGetCommand_AddsToEnvironmentAndSetsDirOrg")

	cmd := SnykCli{}.getCommand([]string{"executable", "arg"}, os.TempDir())

	assert.Equal(t, os.TempDir(), cmd.Dir)
	assert.Contains(t, cmd.Env, "SNYK_CFG_ORG=TestGetCommand_AddsToEnvironmentAndSetsDirOrg")
}
