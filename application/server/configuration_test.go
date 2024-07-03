/*
 * © 2022 Snyk Limited All rights reserved.
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
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/snyk-ls/internal/observability/ux"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"

	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/testutil"
)

var sampleSettings = lsp.Settings{
	ActivateSnykOpenSource:     "false",
	ActivateSnykCode:           "false",
	ActivateSnykIac:            "false",
	Insecure:                   "true",
	Endpoint:                   "https://api.fake.snyk.io",
	AdditionalParams:           "--all-projects -d",
	AdditionalEnv:              "a=b;c=d",
	Path:                       "addPath",
	SendErrorReports:           "true",
	Token:                      "token",
	SnykCodeApi:                "https://deeproxy.fake.snyk.io",
	EnableSnykLearnCodeActions: "true",
}

func keyFoundInEnv(key string) bool {
	found := false
	env := os.Environ()
	fmt.Println(env)
	for _, v := range env {
		if strings.HasPrefix(v, key+"=") {
			found = true
			break
		}
	}
	return found
}

func Test_WorkspaceDidChangeConfiguration_Push(t *testing.T) {
	di.TestInit(t)
	loc, _ := setupServer(t)
	c := config.CurrentConfig()

	t.Setenv("a", "")
	t.Setenv("c", "")
	params := lsp.DidChangeConfigurationParams{Settings: sampleSettings}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	conf := c.Engine().GetConfiguration()
	assert.Equal(t, false, c.IsSnykCodeEnabled())
	assert.Equal(t, false, c.IsSnykOssEnabled())
	assert.Equal(t, false, c.IsSnykIacEnabled())
	assert.True(t, c.CliSettings().Insecure)
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalOssParameters)
	assert.Equal(t, params.Settings.Endpoint, c.SnykApi())
	assert.Equal(t, params.Settings.Endpoint, conf.GetString(configuration.API_URL))
	assert.Equal(t, "b", os.Getenv("a"))
	assert.Equal(t, "d", os.Getenv("c"))
	assert.True(t, strings.Contains(os.Getenv("PATH"), "addPath"))
	assert.True(t, config.CurrentConfig().IsErrorReportingEnabled())
	assert.Equal(t, "token", config.CurrentConfig().Token())
	assert.Equal(t, sampleSettings.SnykCodeApi, config.CurrentConfig().SnykCodeApi())
	assert.Equal(t, sampleSettings.EnableSnykLearnCodeActions, strconv.FormatBool(c.IsSnykLearnCodeActionsEnabled()))
}

func Test_WorkspaceDidChangeConfiguration_Pull(t *testing.T) {
	loc, _ := setupCustomServer(t, callBackMock)
	c := config.CurrentConfig()

	_, err := loc.Client.Call(ctx, "initialize", lsp.InitializeParams{
		Capabilities: lsp.ClientCapabilities{
			Workspace: lsp.WorkspaceClientCapabilities{
				Configuration: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{}}
	_, err = loc.Client.Call(context.Background(), "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}
	assert.NoError(t, err)

	conf := c.Engine().GetConfiguration()
	assert.Equal(t, false, c.IsSnykCodeEnabled())
	assert.Equal(t, false, c.IsSnykOssEnabled())
	assert.Equal(t, false, c.IsSnykIacEnabled())
	assert.True(t, c.CliSettings().Insecure)
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalOssParameters)
	assert.Equal(t, sampleSettings.Endpoint, c.SnykApi())
	assert.Equal(t, c.SnykApi(), conf.GetString(configuration.API_URL))
	assert.True(t, config.CurrentConfig().IsErrorReportingEnabled())
	assert.Equal(t, "token", config.CurrentConfig().Token())
	assert.Equal(t, sampleSettings.SnykCodeApi, config.CurrentConfig().SnykCodeApi())
	assert.Equal(t, sampleSettings.EnableSnykLearnCodeActions, strconv.FormatBool(c.IsSnykLearnCodeActionsEnabled()))
}

func callBackMock(_ context.Context, request *jrpc2.Request) (any, error) {
	if request.Method() == "workspace/configuration" {
		return []lsp.Settings{sampleSettings}, nil
	}
	return nil, nil
}

func Test_WorkspaceDidChangeConfiguration_PullNoCapability(t *testing.T) {
	testutil.UnitTest(t)

	loc, jsonRPCRecorder := setupCustomServer(t, callBackMock)

	params := lsp.DidChangeConfigurationParams{Settings: lsp.Settings{}}
	var updated = true
	err := loc.Client.CallResult(context.Background(), "workspace/didChangeConfiguration", params, &updated)
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	assert.NoError(t, err)
	assert.False(t, updated)
	assert.Eventually(t, func() bool {
		return len(jsonRPCRecorder.Callbacks()) == 0
	}, time.Second, time.Millisecond)
}

func Test_UpdateSettings(t *testing.T) {
	di.TestInit(t)

	orgUuid, _ := uuid.NewRandom()
	expectedOrgId := orgUuid.String()

	t.Run("All settings are updated", func(t *testing.T) {
		c := testutil.UnitTest(t)

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
			Organization:                expectedOrgId,
			EnableTelemetry:             "false",
			ManageBinariesAutomatically: "false",
			CliPath:                     "C:\\Users\\CliPath\\snyk-ls.exe",
			Token:                       "a fancy token",
			FilterSeverity:              lsp.DefaultSeverityFilter(),
			TrustedFolders:              []string{"trustedPath1", "trustedPath2"},
			OsPlatform:                  "windows",
			OsArch:                      "amd64",
			RuntimeName:                 "java",
			RuntimeVersion:              "1.8.0_275",
			ScanningMode:                "manual",
			AuthenticationMethod:        lsp.OAuthAuthentication,
			SnykCodeApi:                 sampleSettings.SnykCodeApi,
		}

		UpdateSettings(c, settings)

		assert.Equal(t, false, c.IsSnykCodeEnabled())
		assert.Equal(t, false, c.IsSnykOssEnabled())
		assert.Equal(t, false, c.IsSnykIacEnabled())
		assert.Equal(t, true, c.CliSettings().Insecure)
		assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalOssParameters)
		assert.Equal(t, "https://snyk.io/api", c.SnykApi())
		assert.Equal(t, "b", os.Getenv("a"))
		assert.Equal(t, "d", os.Getenv("c"))
		assert.True(t, strings.HasPrefix(os.Getenv("PATH"), "addPath"+string(os.PathListSeparator)))
		assert.True(t, c.IsErrorReportingEnabled())
		assert.Equal(t, expectedOrgId, c.Organization())
		assert.False(t, c.IsTelemetryEnabled())
		assert.False(t, c.ManageBinariesAutomatically())
		assert.Equal(t, "C:\\Users\\CliPath\\snyk-ls.exe", c.CliSettings().Path())
		assert.Equal(t, "a fancy token", c.Token())
		assert.Equal(t, lsp.DefaultSeverityFilter(), c.FilterSeverity())
		assert.Subset(t, []string{"trustedPath1", "trustedPath2"}, c.TrustedFolders())
		assert.Equal(t, settings.OsPlatform, c.OsPlatform())
		assert.Equal(t, settings.OsArch, c.OsArch())
		assert.Equal(t, settings.RuntimeName, c.RuntimeName())
		assert.Equal(t, settings.RuntimeVersion, c.RuntimeVersion())
		assert.False(t, c.IsAutoScanEnabled())
		assert.Equal(t, sampleSettings.SnykCodeApi, c.SnykCodeApi())
	})

	t.Run("empty snyk code api is ignored and default is used", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, lsp.Settings{})

		assert.Equal(t, config.DefaultDeeproxyApiUrl, c.SnykCodeApi())
	})

	t.Run("blank organization is ignored", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.SetOrganization(expectedOrgId)

		UpdateSettings(c, lsp.Settings{Organization: " "})

		assert.Equal(t, expectedOrgId, c.Organization())
	})

	t.Run("incomplete env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, lsp.Settings{AdditionalEnv: "a="})

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("empty env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)
		varCount := len(os.Environ())

		UpdateSettings(c, lsp.Settings{AdditionalEnv: " "})

		assert.Equal(t, varCount, len(os.Environ()))
	})

	t.Run("broken env variables", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, lsp.Settings{AdditionalEnv: "a=; b"})

		assert.Empty(t, os.Getenv("a"))
		assert.Empty(t, os.Getenv("b"))
		assert.Empty(t, os.Getenv(";"))
	})
	t.Run("trusted folders", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, lsp.Settings{TrustedFolders: []string{"/a/b", "/b/c"}})

		assert.Contains(t, c.TrustedFolders(), "/a/b")
		assert.Contains(t, c.TrustedFolders(), "/b/c")
	})

	t.Run("manage binaries automatically", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("true", func(t *testing.T) {
			UpdateSettings(c, lsp.Settings{
				ManageBinariesAutomatically: "true",
			})

			assert.True(t, config.CurrentConfig().ManageBinariesAutomatically())
		})
		t.Run("false", func(t *testing.T) {
			UpdateSettings(c, lsp.Settings{
				ManageBinariesAutomatically: "false",
			})

			assert.False(t, config.CurrentConfig().ManageBinariesAutomatically())
		})

		t.Run("invalid value does not update", func(t *testing.T) {
			UpdateSettings(c, lsp.Settings{
				ManageBinariesAutomatically: "true",
			})

			UpdateSettings(c, lsp.Settings{
				ManageBinariesAutomatically: "dog",
			})

			assert.True(t, config.CurrentConfig().ManageBinariesAutomatically())
		})
	})

	t.Run("activateSnykCodeSecurity is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, lsp.Settings{ActivateSnykCodeSecurity: "true"})

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})
	t.Run("activateSnykCodeSecurity is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, lsp.Settings{})

		assert.Equal(t, false, c.IsSnykCodeSecurityEnabled())

		c.EnableSnykCodeSecurity(true)

		UpdateSettings(c, lsp.Settings{})

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})
	t.Run("activateSnykCodeQuality is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, lsp.Settings{ActivateSnykCodeQuality: "true"})

		assert.Equal(t, true, c.IsSnykCodeQualityEnabled())
	})
	t.Run("activateSnykCodeQuality is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, lsp.Settings{})

		assert.Equal(t, false, c.IsSnykCodeQualityEnabled())

		c.EnableSnykCodeQuality(true)

		UpdateSettings(c, lsp.Settings{})

		assert.Equal(t, true, c.IsSnykCodeQualityEnabled())
	})
	t.Run("activateSnykCode sets SnykCodeQuality and SnykCodeSecurity", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, lsp.Settings{
			ActivateSnykCode: "true",
		})

		assert.Equal(t, true, c.IsSnykCodeQualityEnabled())
		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
		assert.Equal(t, true, c.IsSnykCodeEnabled())
	})

	t.Run("severity filter", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedSeverityFilter := lsp.NewSeverityFilter(true, false, true, false)
			UpdateSettings(c, lsp.Settings{FilterSeverity: mixedSeverityFilter})

			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())
		})
	})
}

func Test_ScanningModeChanged_AnalyticsNotified(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)
	analytics := di.Analytics().(*ux.TestAnalytics)
	callCount := analytics.ScanModeIsSelectedCount

	UpdateSettings(c, lsp.Settings{ScanningMode: "manual"})

	assert.Equal(t, callCount+1, analytics.ScanModeIsSelectedCount)
}

func Test_InitializeSettings(t *testing.T) {
	di.TestInit(t)

	t.Run("device ID is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)
		deviceId := "test-device-id"

		InitializeSettings(c, lsp.Settings{DeviceId: deviceId})

		assert.Equal(t, deviceId, c.DeviceID())
	})

	t.Run("device ID is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)
		deviceId := c.DeviceID()

		InitializeSettings(c, lsp.Settings{})

		assert.Equal(t, deviceId, c.DeviceID())
	})

	t.Run("activateSnykCodeSecurity is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, lsp.Settings{ActivateSnykCodeSecurity: "true"})

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})
	t.Run("activateSnykCodeSecurity is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, lsp.Settings{})

		assert.Equal(t, false, c.IsSnykCodeSecurityEnabled())

		c.EnableSnykCodeSecurity(true)

		InitializeSettings(c, lsp.Settings{})

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})
	t.Run("activateSnykCodeQuality is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, lsp.Settings{ActivateSnykCodeQuality: "true"})

		assert.Equal(t, true, c.IsSnykCodeQualityEnabled())
	})
	t.Run("activateSnykCodeQuality is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, lsp.Settings{})

		assert.Equal(t, false, c.IsSnykCodeQualityEnabled())

		c.EnableSnykCodeQuality(true)

		InitializeSettings(c, lsp.Settings{})

		assert.Equal(t, true, c.IsSnykCodeQualityEnabled())
	})

	t.Run("custom path configuration", func(t *testing.T) {
		c := testutil.UnitTest(t)

		first := "first"
		second := "second"

		upperCasePathKey := "PATH"
		caseSensitivePathKey := "Path"
		t.Setenv(caseSensitivePathKey, "something_meaningful")

		// update path to hold a custom value
		UpdateSettings(c, lsp.Settings{Path: first})
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), first+string(os.PathListSeparator)))

		// update path to hold another value
		UpdateSettings(c, lsp.Settings{Path: second})
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), second+string(os.PathListSeparator)))
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), first))

		// reset path with non-empty settings
		UpdateSettings(c, lsp.Settings{Path: "", AuthenticationMethod: "token"})
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), second))

		assert.True(t, keyFoundInEnv(upperCasePathKey))
		assert.False(t, keyFoundInEnv(caseSensitivePathKey))
	})
}
