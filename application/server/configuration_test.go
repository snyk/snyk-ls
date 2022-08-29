package server

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/creachadair/jrpc2"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/testutil"
)

var sampleSettings = lsp.InitializationOptions{
	ActivateSnykOpenSource: "false",
	ActivateSnykCode:       "false",
	ActivateSnykIac:        "false",
	Insecure:               "true",
	Endpoint:               "asd",
	AdditionalParams:       "--all-projects -d",
	AdditionalEnv:          "a=b;c=d",
	Path:                   "addPath",
	SendErrorReports:       "true",
	Token:                  "token",
}

func Test_WorkspaceDidChangeConfiguration_Push(t *testing.T) {
	testutil.UnitTest(t)
	loc := setupServer(t)

	t.Setenv("a", "")
	t.Setenv("c", "")
	params := lsp.DidChangeConfigurationParams{Settings: sampleSettings}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	c := config.CurrentConfig()
	assert.Equal(t, false, c.IsSnykCodeEnabled())
	assert.Equal(t, false, c.IsSnykOssEnabled())
	assert.Equal(t, false, c.IsSnykIacEnabled())
	assert.Equal(t, true, c.CliSettings().Insecure)
	assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalParameters)
	assert.Equal(t, params.Settings.Endpoint, c.SnykApi())
	assert.Equal(t, "b", os.Getenv("a"))
	assert.Equal(t, "d", os.Getenv("c"))
	assert.True(t, strings.Contains(os.Getenv("PATH"), "addPath"))
	assert.True(t, config.CurrentConfig().IsErrorReportingEnabled())
	assert.Equal(t, "token", config.CurrentConfig().Token())
}

func callBackMock(ctx context.Context, request *jrpc2.Request) (interface{}, error) {
	jsonRPCRecorder.Record(*request)
	if request.Method() == "workspace/configuration" {
		return []lsp.InitializationOptions{sampleSettings}, nil
	}
	return nil, nil
}

func Test_WorkspaceDidChangeConfiguration_Pull(t *testing.T) {
	testutil.UnitTest(t)
	loc := setupCustomServer(t, callBackMock)

	_, err := loc.Client.Call(ctx, "initialize", lsp.InitializeParams{
		Capabilities: sglsp.ClientCapabilities{
			Workspace: sglsp.WorkspaceClientCapabilities{
				Configuration: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	params := lsp.DidChangeConfigurationParams{Settings: lsp.InitializationOptions{}}
	ctx := context.Background()
	_, err = loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}
	assert.NoError(t, err)

	c := config.CurrentConfig()
	assert.Equal(t, false, c.IsSnykCodeEnabled())
	assert.Equal(t, false, c.IsSnykOssEnabled())
	assert.Equal(t, false, c.IsSnykIacEnabled())
	assert.Equal(t, true, c.CliSettings().Insecure)
	assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalParameters)
	assert.Equal(t, "asd", c.SnykApi())
	assert.True(t, config.CurrentConfig().IsErrorReportingEnabled())
	assert.Equal(t, "token", config.CurrentConfig().Token())
}

func Test_WorkspaceDidChangeConfiguration_PullNoCapability(t *testing.T) {
	testutil.UnitTest(t)
	loc := setupCustomServer(t, callBackMock)

	params := lsp.DidChangeConfigurationParams{Settings: lsp.InitializationOptions{}}
	ctx := context.Background()
	var updated = true
	err := loc.Client.CallResult(ctx, "workspace/didChangeConfiguration", params, &updated)
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	assert.NoError(t, err)
	assert.False(t, updated)
}

func Test_UpdateSettings(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)

	t.Run("all settings", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		settings := lsp.InitializationOptions{
			ActivateSnykOpenSource:      "false",
			ActivateSnykCode:            "false",
			ActivateSnykIac:             "false",
			Insecure:                    "true",
			Endpoint:                    "https://snyk.io/api",
			AdditionalParams:            "--all-projects -d",
			AdditionalEnv:               "a=b;c=d",
			Path:                        "addPath",
			SendErrorReports:            "true",
			Organization:                "org",
			EnableTelemetry:             "false",
			ManageBinariesAutomatically: "false",
			CliPath:                     "C:\\Users\\CliPath\\snyk-ls.exe",
			Token:                       "a fancy token",
		}

		UpdateSettings(context.Background(), settings)

		c := config.CurrentConfig()
		assert.Equal(t, false, c.IsSnykCodeEnabled())
		assert.Equal(t, false, c.IsSnykOssEnabled())
		assert.Equal(t, false, c.IsSnykIacEnabled())
		assert.Equal(t, true, c.CliSettings().Insecure)
		assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalParameters)
		assert.Equal(t, "https://snyk.io/api", c.SnykApi())
		assert.Equal(t, "b", os.Getenv("a"))
		assert.Equal(t, "d", os.Getenv("c"))
		assert.True(t, strings.Contains(os.Getenv("PATH"), "addPath"))
		assert.True(t, c.IsErrorReportingEnabled())
		assert.Equal(t, "org", c.GetOrganization())
		assert.False(t, c.IsTelemetryEnabled())
		assert.False(t, c.ManageBinariesAutomatically())
		assert.Equal(t, "C:\\Users\\CliPath\\snyk-ls.exe", c.CliSettings().Path())
		assert.Equal(t, "a fancy token", c.Token())
	})

	t.Run("blank organisation is ignored", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		UpdateSettings(context.Background(), lsp.InitializationOptions{Organization: " "})

		c := config.CurrentConfig()
		assert.Equal(t, "", c.GetOrganization())
	})

	t.Run("incomplete env vars", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		UpdateSettings(context.Background(), lsp.InitializationOptions{AdditionalEnv: "a="})

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("empty env vars", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		UpdateSettings(context.Background(), lsp.InitializationOptions{AdditionalEnv: " "})

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("broken env variables", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		UpdateSettings(context.Background(), lsp.InitializationOptions{AdditionalEnv: "a=; b"})

		c := config.CurrentConfig()
		assert.Equal(t, "", c.GetOrganization())
		assert.Empty(t, os.Getenv("a"))
		assert.Empty(t, os.Getenv("b"))
		assert.Empty(t, os.Getenv(";"))
	})

	t.Run("manage binaries automatically", func(t *testing.T) {
		t.Run("true", func(t *testing.T) {
			UpdateSettings(context.Background(), lsp.InitializationOptions{
				ManageBinariesAutomatically: "true",
			})

			assert.True(t, config.CurrentConfig().ManageBinariesAutomatically())
		})
		t.Run("false", func(t *testing.T) {
			UpdateSettings(context.Background(), lsp.InitializationOptions{
				ManageBinariesAutomatically: "false",
			})

			assert.False(t, config.CurrentConfig().ManageBinariesAutomatically())
		})
		t.Run("invalid value does not update", func(t *testing.T) {
			UpdateSettings(context.Background(), lsp.InitializationOptions{
				ManageBinariesAutomatically: "true",
			})

			UpdateSettings(context.Background(), lsp.InitializationOptions{
				ManageBinariesAutomatically: "dog",
			})

			assert.True(t, config.CurrentConfig().ManageBinariesAutomatically())
		})
	})

	t.Run("Auto authenticate", func(t *testing.T) {
		t.Run("true when not included", func(t *testing.T) {
			UpdateSettings(context.Background(), lsp.InitializationOptions{})
			assert.True(t, config.CurrentConfig().AutomaticAuthentication())
		})

		t.Run("Parses true value", func(t *testing.T) {
			UpdateSettings(context.Background(), lsp.InitializationOptions{
				AutomaticAuthentication: "true",
			})
			assert.True(t, config.CurrentConfig().AutomaticAuthentication())
		})

		t.Run("Parses false value", func(t *testing.T) {
			UpdateSettings(context.Background(), lsp.InitializationOptions{
				AutomaticAuthentication: "false",
			})
			assert.False(t, config.CurrentConfig().AutomaticAuthentication())
		})
	})
}
