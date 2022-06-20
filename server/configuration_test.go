package server

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/lsp"
)

func TestWorkspaceDidChangeConfiguration(t *testing.T) {
	testutil.UnitTest(t)
	loc := setupServer(t)

	t.Setenv("a", "")
	t.Setenv("c", "")
	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		ActivateSnykOpenSource: "false",
		ActivateSnykCode:       "false",
		ActivateSnykIac:        "false",
		Insecure:               "true",
		Endpoint:               "asd",
		AdditionalParams:       "--all-projects -d",
		AdditionalEnv:          "a=b;c=d",
		Path:                   "addPath",
		SendErrorReports:       "true",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(t, err, "error calling server")
	}

	c := config.CurrentConfig()
	assert.Equal(t, false, c.IsSnykCodeEnabled())
	assert.Equal(t, false, c.IsSnykOssEnabled())
	assert.Equal(t, false, c.IsSnykIacEnabled())
	assert.Equal(t, true, c.CliSettings().Insecure)
	assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalParameters)
	assert.Equal(t, params.Settings.Endpoint, c.CliSettings().Endpoint)
	assert.Equal(t, "b", os.Getenv("a"))
	assert.Equal(t, "d", os.Getenv("c"))
	assert.True(t, strings.Contains(os.Getenv("PATH"), "addPath"))
	assert.True(t, config.CurrentConfig().IsErrorReportingEnabled())
}

func TestWorkspaceDidChangeConfiguration_IncompleteEnvVars(t *testing.T) {
	loc := setupServer(t)

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		AdditionalEnv: "a=",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(t, err, "error calling server")
	}

	assert.Empty(t, os.Getenv("a"))
}

func TestWorkspaceDidChangeConfiguration_EmptyEnvVars(t *testing.T) {
	loc := setupServer(t)

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		AdditionalEnv: "",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(t, err, "error calling server")
	}

	assert.Empty(t, os.Getenv("a"))
}

func TestWorkspaceDidChangeConfiguration_WeirdEnvVars(t *testing.T) {
	loc := setupServer(t)

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		AdditionalEnv: "a=; b",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(t, err, "error calling server")
	}

	assert.Empty(t, os.Getenv("a"))
	assert.Empty(t, os.Getenv("b"))
	assert.Empty(t, os.Getenv(";"))
}

func TestWorkspaceDidChangeConfiguration_UpdateOrganization(t *testing.T) {
	loc := setupServer(t)

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		Organization: "snyk-test-org",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(t, err, "error calling server")
	}

	assert.Equal(t, "snyk-test-org", config.CurrentConfig().GetOrganization())
}

func TestWorkspaceDidChangeConfiguration_IgnoreBlankOrganization(t *testing.T) {
	loc := setupServer(t)

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		Organization: " ",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(t, err, "error calling server")
	}

	assert.Equal(t, "", config.CurrentConfig().GetOrganization())
}

func TestWorkspaceDidChangeConfiguration_UpdateSendTelemetry(t *testing.T) {
	loc := setupServer(t)

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		EnableTelemetry: "true",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(t, err, "error calling server")
	}

	assert.Equal(t, true, config.CurrentConfig().IsTelemetryEnabled())
}
