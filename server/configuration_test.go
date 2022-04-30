package server

import (
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/lsp"
)

func TestWorkspaceDidChangeConfiguration(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)
	os.Unsetenv("a")
	os.Unsetenv("c")
	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		ActivateSnykOpenSource: "false",
		ActivateSnykCode:       "false",
		ActivateSnykIac:        "false",
		Insecure:               "true",
		Endpoint:               "asd",
		AdditionalParams:       "--all-projects -d",
		AdditionalEnv:          "a=b;c=d",
		Path:                   "addPath",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		log.Fatal().Err(err).Msg("error calling server")
	}

	p := environment.CurrentEnabledProducts
	assert.Equal(t, false, p.Code)
	assert.Equal(t, false, p.OpenSource)
	assert.Equal(t, false, p.Iac)
	assert.Equal(t, true, cli.CurrentSettings.Insecure)
	assert.Equal(t, []string{"--all-projects", "-d"}, cli.CurrentSettings.AdditionalParameters)
	assert.Equal(t, params.Settings.Endpoint, cli.CurrentSettings.Endpoint)
	assert.Equal(t, "b", os.Getenv("a"))
	assert.Equal(t, "d", os.Getenv("c"))
	assert.True(t, strings.Contains(os.Getenv("PATH"), "addPath"))
}

func TestWorkspaceDidChangeConfiguration_IncompleteEnvVars(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)
	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		AdditionalEnv: "a=",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		log.Fatal().Err(err).Msg("error calling server")
	}

	assert.Empty(t, os.Getenv("a"))
}

func TestWorkspaceDidChangeConfiguration_EmptyEnvVars(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)
	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		AdditionalEnv: "",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		log.Fatal().Err(err).Msg("error calling server")
	}

	assert.Empty(t, os.Getenv("a"))
}

func TestWorkspaceDidChangeConfiguration_WeirdEnvVars(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)
	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{
		AdditionalEnv: "a=; b",
	}}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		log.Fatal().Err(err).Msg("error calling server")
	}

	assert.Empty(t, os.Getenv("a"))
	assert.Empty(t, os.Getenv("b"))
	assert.Empty(t, os.Getenv(";"))
}
