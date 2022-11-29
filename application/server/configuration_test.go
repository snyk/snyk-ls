/*
 * Copyright 2022 Snyk Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

var sampleSettings = lsp.Settings{
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

func callBackMock(_ context.Context, request *jrpc2.Request) (interface{}, error) {
	jsonRPCRecorder.Record(*request)
	if request.Method() == "workspace/configuration" {
		return []lsp.Settings{sampleSettings}, nil
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

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{}}
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

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{}}
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

		settings := lsp.Settings{
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
			TrustedFolders:              []string{"trustedPath1", "trustedPath2"},
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
		assert.Contains(t, c.TrustedFolders(), "trustedPath1")
		assert.Contains(t, c.TrustedFolders(), "trustedPath2")
	})

	t.Run("blank organisation is ignored", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		UpdateSettings(context.Background(), lsp.Settings{Organization: " "})

		c := config.CurrentConfig()
		assert.Equal(t, "", c.GetOrganization())
	})

	t.Run("incomplete env vars", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		UpdateSettings(context.Background(), lsp.Settings{AdditionalEnv: "a="})

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("empty env vars", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		UpdateSettings(context.Background(), lsp.Settings{AdditionalEnv: " "})

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("broken env variables", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		UpdateSettings(context.Background(), lsp.Settings{AdditionalEnv: "a=; b"})

		c := config.CurrentConfig()
		assert.Equal(t, "", c.GetOrganization())
		assert.Empty(t, os.Getenv("a"))
		assert.Empty(t, os.Getenv("b"))
		assert.Empty(t, os.Getenv(";"))
	})
	t.Run("trusted folders", func(t *testing.T) {
		config.SetCurrentConfig(config.New())

		UpdateSettings(context.Background(), lsp.Settings{TrustedFolders: []string{"/a/b", "/b/c"}})

		c := config.CurrentConfig()
		assert.Contains(t, c.TrustedFolders(), "/a/b")
		assert.Contains(t, c.TrustedFolders(), "/b/c")
	})

	t.Run("manage binaries automatically", func(t *testing.T) {
		t.Run("true", func(t *testing.T) {
			UpdateSettings(context.Background(), lsp.Settings{
				ManageBinariesAutomatically: "true",
			})

			assert.True(t, config.CurrentConfig().ManageBinariesAutomatically())
		})
		t.Run("false", func(t *testing.T) {
			UpdateSettings(context.Background(), lsp.Settings{
				ManageBinariesAutomatically: "false",
			})

			assert.False(t, config.CurrentConfig().ManageBinariesAutomatically())
		})
		t.Run("invalid value does not update", func(t *testing.T) {
			UpdateSettings(context.Background(), lsp.Settings{
				ManageBinariesAutomatically: "true",
			})

			UpdateSettings(context.Background(), lsp.Settings{
				ManageBinariesAutomatically: "dog",
			})

			assert.True(t, config.CurrentConfig().ManageBinariesAutomatically())
		})
	})
}

func Test_InitializeSettings(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)

	t.Run("device ID is passed", func(t *testing.T) {
		config.SetCurrentConfig(config.New())
		deviceId := "test-device-id"

		InitializeSettings(context.Background(), lsp.Settings{DeviceId: deviceId})

		c := config.CurrentConfig()
		assert.Equal(t, deviceId, c.DeviceID())
	})

	t.Run("device ID is not passed", func(t *testing.T) {
		config.SetCurrentConfig(config.New())
		curentDeviceId := config.CurrentConfig().DeviceID()

		InitializeSettings(context.Background(), lsp.Settings{})

		c := config.CurrentConfig()
		assert.Equal(t, curentDeviceId, c.DeviceID())
	})
}
