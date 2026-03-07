/*
 * © 2022-2026 Snyk Limited All rights reserved.
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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"

	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

var sampleSettings = map[string]*types.ConfigSetting{
	types.SettingSnykOssEnabled:             {Value: false, Changed: true},
	types.SettingSnykCodeEnabled:            {Value: false, Changed: true},
	types.SettingSnykIacEnabled:             {Value: false, Changed: true},
	types.SettingProxyInsecure:              {Value: true, Changed: true},
	types.SettingApiEndpoint:                {Value: "https://api.fake.snyk.io", Changed: true},
	types.SettingAdditionalParameters:       {Value: "--all-projects -d", Changed: true},
	types.SettingAdditionalEnvironment:      {Value: "a=b;c=d", Changed: true},
	types.SettingSendErrorReports:           {Value: true, Changed: true},
	types.SettingToken:                      {Value: "token", Changed: true},
	types.SettingCodeEndpoint:               {Value: "https://deeproxy.fake.snyk.io", Changed: true},
	types.SettingEnableSnykLearnCodeActions: {Value: true, Changed: true},
}

func keyFoundInEnv(key string) bool {
	found := false
	env := os.Environ()
	for _, v := range env {
		if strings.HasPrefix(v, key+"=") {
			found = true
			break
		}
	}
	return found
}

func Test_WorkspaceDidChangeConfiguration_Push(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)
	loc, _ := setupServer(t, c)

	// Wait for default environment to be ready before testing PATH updates
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := c.WaitForDefaultEnv(ctx)
	if err != nil {
		t.Fatal(err, "error waiting for default environment")
	}

	t.Setenv("a", "")
	t.Setenv("c", "")
	// Path is init-only; call initialize first with Path in InitializationOptions
	_, _ = loc.Client.Call(t.Context(), "initialize", types.InitializeParams{
		Capabilities: types.ClientCapabilities{},
		InitializationOptions: types.InitializationOptions{
			Path: "addPath",
		},
	})
	params := types.DidChangeConfigurationParams{Settings: sampleSettings, FolderConfigs: nil}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	conf := c.Engine().GetConfiguration()
	assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))
	assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykOssEnabled)))
	assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykIacEnabled)))
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingCliInsecure)))
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	ossParams, ok := c.Engine().GetConfiguration().Get(configuration.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"--all-projects", "-d"}, ossParams)
	assert.Equal(t, "https://api.fake.snyk.io", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingApiEndpoint)))
	assert.Equal(t, c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingApiEndpoint)), conf.GetString(configuration.API_URL))
	assert.Equal(t, "b", os.Getenv("a"))
	assert.Equal(t, "d", os.Getenv("c"))
	assert.True(t, strings.Contains(os.Getenv("PATH"), "addPath"))
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSendErrorReports)))
	assert.Equal(t, "token", config.GetToken(c.Engine().GetConfiguration()))
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingEnableSnykLearnCodeActions)))
}

func Test_WorkspaceDidChangeConfiguration_Pull(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, _ := setupCustomServer(t, c, callBackMock)

	_, err := loc.Client.Call(t.Context(), "initialize", types.InitializeParams{
		Capabilities: types.ClientCapabilities{
			Workspace: types.WorkspaceClientCapabilities{
				Configuration: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	params := types.DidChangeConfigurationParams{Settings: map[string]*types.ConfigSetting{}, FolderConfigs: nil}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}
	assert.NoError(t, err)

	conf := c.Engine().GetConfiguration()
	assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))
	assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykOssEnabled)))
	assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykIacEnabled)))
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingCliInsecure)))
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	ossParams, ok := c.Engine().GetConfiguration().Get(configuration.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"--all-projects", "-d"}, ossParams)
	assert.Equal(t, "https://api.fake.snyk.io", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingApiEndpoint)))
	assert.Equal(t, c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingApiEndpoint)), conf.GetString(configuration.API_URL))
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSendErrorReports)))
	assert.Equal(t, "token", config.GetToken(c.Engine().GetConfiguration()))
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingEnableSnykLearnCodeActions)))
}

func callBackMock(_ context.Context, request *jrpc2.Request) (any, error) {
	if request.Method() == "workspace/configuration" {
		return []types.DidChangeConfigurationParams{{Settings: sampleSettings, FolderConfigs: nil}}, nil
	}
	return nil, nil
}

func Test_WorkspaceDidChangeConfiguration_PullNoCapability(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupCustomServer(t, c, callBackMock)

	params := types.DidChangeConfigurationParams{Settings: map[string]*types.ConfigSetting{}, FolderConfigs: nil}
	var updated = true
	err := loc.Client.CallResult(t.Context(), "workspace/didChangeConfiguration", params, &updated)
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
	orgUuid, _ := uuid.NewRandom()
	expectedOrgId := orgUuid.String()

	t.Run("All settings are updated", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		tempDir1 := filepath.Join(t.TempDir(), "tempDir1")
		tempDir2 := filepath.Join(t.TempDir(), "tempDir2")
		nonDefaultSeverityFilter := types.NewSeverityFilter(false, true, false, true)
		nonDefaultIssueViewOptions := types.NewIssueViewOptions(false, true)
		cliDir := t.TempDir()
		hoverVerbosity := 1
		outputFormat := "html"
		settingsMap := map[string]*types.ConfigSetting{
			types.SettingSnykOssEnabled:               {Value: false, Changed: true},
			types.SettingSnykCodeEnabled:              {Value: false, Changed: true},
			types.SettingSnykIacEnabled:               {Value: false, Changed: true},
			types.SettingProxyInsecure:                {Value: true, Changed: true},
			types.SettingApiEndpoint:                  {Value: "https://api.snyk.io", Changed: true},
			types.SettingAdditionalParameters:         {Value: "--all-projects -d", Changed: true},
			types.SettingAdditionalEnvironment:        {Value: "a=b;c=d", Changed: true},
			types.SettingSendErrorReports:             {Value: true, Changed: true},
			types.SettingOrganization:                 {Value: expectedOrgId, Changed: true},
			types.SettingAutomaticDownload:            {Value: false, Changed: true},
			types.SettingCliPath:                      {Value: filepath.Join(cliDir, "cli"), Changed: true},
			types.SettingToken:                        {Value: "a fancy token", Changed: true},
			types.SettingEnabledSeverities:            {Value: map[string]interface{}{"critical": false, "high": true, "medium": false, "low": true}, Changed: true},
			types.SettingIssueViewOpenIssues:          {Value: false, Changed: true},
			types.SettingIssueViewIgnoredIssues:       {Value: true, Changed: true},
			types.SettingTrustEnabled:                 {Value: true, Changed: true},
			types.SettingScanAutomatic:                {Value: "manual", Changed: true},
			types.SettingAuthenticationMethod:         {Value: string(types.FakeAuthentication), Changed: true},
			types.SettingEnableSnykOpenBrowserActions: {Value: true, Changed: true},
		}
		folderConfigs := []types.LspFolderConfig{
			{
				FolderPath: types.FilePath(tempDir1),
				Settings: map[string]*types.ConfigSetting{
					types.SettingBaseBranch:           {Value: "testBaseBranch1"},
					types.SettingAdditionalParameters: {Value: []string{"--file=asdf"}},
				},
			},
			{
				FolderPath: types.FilePath(tempDir2),
				Settings: map[string]*types.ConfigSetting{
					types.SettingBaseBranch: {Value: "testBaseBranch2"},
				},
			},
		}

		err := initTestRepo(t, tempDir1)
		assert.NoError(t, err)

		err = initTestRepo(t, tempDir2)
		assert.NoError(t, err)

		// Path and TrustedFolders are init-only; apply via InitializeSettings first
		InitializeSettings(c, types.InitializationOptions{
			Path:           "addPath",
			TrustedFolders: []string{"trustedPath1", "trustedPath2"},
			OsPlatform:     "windows",
			OsArch:         "amd64",
			RuntimeName:    "java",
			RuntimeVersion: "1.8.0_275",
			HoverVerbosity: &hoverVerbosity,
			OutputFormat:   &outputFormat,
		})
		UpdateSettings(c, settingsMap, folderConfigs, analytics.TriggerSourceTest)

		assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))
		assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykOssEnabled)))
		assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykIacEnabled)))
		assert.Equal(t, true, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingCliInsecure)))
		ossParams, ok := c.Engine().GetConfiguration().Get(configuration.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string)
		require.True(t, ok)
		assert.Equal(t, []string{"--all-projects", "-d"}, ossParams)
		assert.Equal(t, "https://api.snyk.io", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingApiEndpoint)))
		assert.Equal(t, "b", os.Getenv("a"))
		assert.Equal(t, "d", os.Getenv("c"))
		assert.True(t, strings.HasPrefix(os.Getenv("PATH"), "addPath"+string(os.PathListSeparator)))
		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSendErrorReports)))
		// Organization is set globally but may be cleared at folder level by LDX-Sync logic
		// when it matches the global org and is not the default
		assert.Equal(t, expectedOrgId, c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION))
		assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingAutomaticDownload)))
		assert.Equal(t, filepath.Join(cliDir, "cli"), c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingCliPath)))
		assert.Equal(t, nonDefaultSeverityFilter, config.GetFilterSeverity(c.Engine().GetConfiguration()))
		assert.Equal(t, nonDefaultIssueViewOptions, config.GetIssueViewOptions(c.Engine().GetConfiguration()))
		tf, _ := c.Engine().GetConfiguration().Get(configuration.UserGlobalKey(types.SettingTrustedFolders)).([]types.FilePath)
		assert.Subset(t, []types.FilePath{"trustedPath1", "trustedPath2"}, tf)
		conf := c.Engine().GetConfiguration()
		assert.Equal(t, "windows", conf.GetString(configuration.UserGlobalKey(types.SettingOsPlatform)))
		assert.Equal(t, "amd64", conf.GetString(configuration.UserGlobalKey(types.SettingOsArch)))
		assert.Equal(t, "java", conf.GetString(configuration.UserGlobalKey(types.SettingRuntimeName)))
		assert.Equal(t, "1.8.0_275", conf.GetString(configuration.UserGlobalKey(types.SettingRuntimeVersion)))
		assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingScanAutomatic)))
		assert.Equal(t, true, conf.GetBool(configuration.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions)))
		assert.Equal(t, 1, c.Engine().GetConfiguration().GetInt(configuration.UserGlobalKey(types.SettingHoverVerbosity)))
		assert.Equal(t, "html", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingFormat)))

		folderConfig1 := config.GetFolderConfigFromEngine(c.Engine(), c.GetConfigResolver(), types.FilePath(tempDir1), c.Logger())
		assert.NotEmpty(t, folderConfig1.BaseBranch())
		// AdditionalParameters are preserved through the update
		if len(folderConfig1.AdditionalParameters()) > 0 {
			addlParams := folderConfigs[0].Settings[types.SettingAdditionalParameters]
			require.NotNil(t, addlParams)
			addlParamsSlice := addlParams.Value.([]string)
			assert.Equal(t, addlParamsSlice[0], folderConfig1.AdditionalParameters()[0])
		}
		// With dynamic persistence, org is set from global when UpdateFolderConfigOrg runs.
		// Global org is expectedOrgId; folder org may be set from LDX-Sync or inherit from global.
		assert.Equal(t, expectedOrgId, folderConfig1.PreferredOrg(), "PreferredOrg should be set from global or LDX-Sync")

		folderConfig2 := config.GetFolderConfigFromEngine(c.Engine(), c.GetConfigResolver(), types.FilePath(tempDir2), c.Logger())
		assert.NotEmpty(t, folderConfig2.BaseBranch())
		assert.Empty(t, folderConfig2.AdditionalParameters())
		assert.Equal(t, expectedOrgId, folderConfig2.PreferredOrg(), "PreferredOrg should be set from global or LDX-Sync")

		assert.Eventually(t, func() bool { return config.GetToken(c.Engine().GetConfiguration()) == "a fancy token" }, time.Second*5, time.Millisecond)
	})

	t.Run("hover defaults are set", func(t *testing.T) {
		c := testutil.UnitTest(t)
		UpdateSettings(c, map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest)

		assert.Equal(t, 3, c.Engine().GetConfiguration().GetInt(configuration.UserGlobalKey(types.SettingHoverVerbosity)))
		assert.Equal(t, c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingFormat)), config.FormatMd)
	})

	t.Run("incomplete env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingAdditionalEnvironment: {Value: "a=", Changed: true}}, nil, analytics.TriggerSourceTest)

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("empty env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)
		varCount := len(os.Environ())

		UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingAdditionalEnvironment: {Value: " ", Changed: true}}, nil, analytics.TriggerSourceTest)

		assert.Equal(t, varCount, len(os.Environ()))
	})

	t.Run("broken env variables", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingAdditionalEnvironment: {Value: "a=; b", Changed: true}}, nil, analytics.TriggerSourceTest)

		assert.Empty(t, os.Getenv("a"))
		assert.Empty(t, os.Getenv("b"))
		assert.Empty(t, os.Getenv(";"))
	})
	t.Run("trusted folders", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		// Use platform-appropriate paths; TrustedFolders is init-only, use InitializeSettings
		path1 := filepath.Join("a", "b")
		path2 := filepath.Join("b", "c")
		InitializeSettings(c, types.InitializationOptions{TrustedFolders: []string{path1, path2}})

		tf, _ := c.Engine().GetConfiguration().Get(configuration.UserGlobalKey(types.SettingTrustedFolders)).([]types.FilePath)
		assert.Contains(t, tf, types.FilePath(path1))
		assert.Contains(t, tf, types.FilePath(path2))
	})

	t.Run("manage binaries automatically", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("true", func(t *testing.T) {
			UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest)

			assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingAutomaticDownload)))
		})
		t.Run("false", func(t *testing.T) {
			UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: false, Changed: true}}, nil, analytics.TriggerSourceTest)

			assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingAutomaticDownload)))
		})

		t.Run("invalid value does not update", func(t *testing.T) {
			UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest)

			UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: "dog", Changed: true}}, nil, analytics.TriggerSourceTest)

			assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingAutomaticDownload)))
		})
	})

	t.Run("activateSnykCodeSecurity enables SnykCode via OR", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest)

		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)), "snyk_code_enabled should enable Snyk Code")
	})
	t.Run("activateSnykCode and activateSnykCodeSecurity are ORed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest)

		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)), "Should be enabled when snyk_code_enabled is true")
	})
	t.Run("activateSnykCode alone enables SnykCode", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest)

		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))
	})
	t.Run("neither activateSnykCode nor activateSnykCodeSecurity disables SnykCode", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: false, Changed: true}}, nil, analytics.TriggerSourceTest)

		assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))
	})

	t.Run("activateSnykSecrets is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingSnykSecretsEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest)

		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled)))
	})
	t.Run("activateSnykSecrets false", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingSnykSecretsEnabled: {Value: false, Changed: true}}, nil, analytics.TriggerSourceTest)

		assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled)))
	})
	t.Run("activateSnykSecrets not passed does not update", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		UpdateSettings(c, map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest)

		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled)))
	})

	t.Run("severity filter", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(true, false, true, false)
			UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingEnabledSeverities: {Value: map[string]interface{}{"critical": true, "high": false, "medium": true, "low": false}, Changed: true}}, nil, analytics.TriggerSourceTest)

			assert.Equal(t, mixedSeverityFilter, config.GetFilterSeverity(c.Engine().GetConfiguration()))
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeSeverityFilter := types.NewSeverityFilter(false, false, false, false)
			UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingEnabledSeverities: {Value: map[string]interface{}{"critical": false, "high": false, "medium": false, "low": false}, Changed: true}}, nil, analytics.TriggerSourceTest)

			assert.Equal(t, emptyLikeSeverityFilter, config.GetFilterSeverity(c.Engine().GetConfiguration()))
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(false, false, true, false)
			UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingEnabledSeverities: {Value: map[string]interface{}{"critical": false, "high": false, "medium": true, "low": false}, Changed: true}}, nil, analytics.TriggerSourceTest)
			assert.Equal(t, mixedSeverityFilter, config.GetFilterSeverity(c.Engine().GetConfiguration()))

			UpdateSettings(c, map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest)
			assert.Equal(t, mixedSeverityFilter, config.GetFilterSeverity(c.Engine().GetConfiguration()))
		})
	})

	t.Run("issue view options", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(c, map[string]*types.ConfigSetting{
				types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				types.SettingIssueViewIgnoredIssues: {Value: true, Changed: true},
			}, nil, analytics.TriggerSourceTest)

			assert.Equal(t, mixedIssueViewOptions, config.GetIssueViewOptions(c.Engine().GetConfiguration()))
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeIssueViewOptions := types.NewIssueViewOptions(false, false)
			UpdateSettings(c, map[string]*types.ConfigSetting{
				types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				types.SettingIssueViewIgnoredIssues: {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest)

			assert.Equal(t, emptyLikeIssueViewOptions, config.GetIssueViewOptions(c.Engine().GetConfiguration()))
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(c, map[string]*types.ConfigSetting{
				types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				types.SettingIssueViewIgnoredIssues: {Value: true, Changed: true},
			}, nil, analytics.TriggerSourceTest)
			assert.Equal(t, mixedIssueViewOptions, config.GetIssueViewOptions(c.Engine().GetConfiguration()))

			UpdateSettings(c, map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest)
			assert.Equal(t, mixedIssueViewOptions, config.GetIssueViewOptions(c.Engine().GetConfiguration()))
		})
	})
}

func initTestRepo(t *testing.T, tempDir string) error {
	t.Helper()
	repo1, err := git.PlainInit(tempDir, false)
	assert.NoError(t, err)
	absoluteFileName := filepath.Join(tempDir, "testFile")
	err = os.WriteFile(absoluteFileName, []byte("testData"), 0600)
	assert.NoError(t, err)
	worktree, err := repo1.Worktree()
	assert.NoError(t, err)
	_, err = worktree.Add(filepath.Base(absoluteFileName))
	assert.NoError(t, err)
	_, err = worktree.Commit("testCommit", &git.CommitOptions{
		Author: &object.Signature{Name: t.Name()},
	})
	assert.NoError(t, err)
	return err
}

func Test_UpdateSettings_TokenChange_TriggersLdxSyncRefresh(t *testing.T) {
	t.Run("new token triggers refresh", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLdx := mock_command.NewMockLdxSyncService(ctrl)
		originalService := di.LdxSyncService()
		di.SetLdxSyncService(mockLdx)
		defer di.SetLdxSyncService(originalService)

		folderPath := types.FilePath(t.TempDir())
		workspaceutil.SetupWorkspace(t, c, folderPath)

		c.SetToken("old-token")

		folders := c.Workspace().Folders()
		mockLdx.EXPECT().
			RefreshConfigFromLdxSync(gomock.Any(), c, gomock.Eq(folders), gomock.Any()).
			Times(1)

		UpdateSettings(c, map[string]*types.ConfigSetting{
			types.SettingToken: {Value: "new-token", Changed: true},
		}, nil, analytics.TriggerSourceTest)
	})

	t.Run("same token does not trigger refresh", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLdx := mock_command.NewMockLdxSyncService(ctrl)
		originalService := di.LdxSyncService()
		di.SetLdxSyncService(mockLdx)
		defer di.SetLdxSyncService(originalService)

		folderPath := types.FilePath(t.TempDir())
		workspaceutil.SetupWorkspace(t, c, folderPath)

		c.SetToken("same-token")

		// No expectation for RefreshConfigFromLdxSync — must NOT be called
		mockLdx.EXPECT().
			RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Times(0)

		UpdateSettings(c, map[string]*types.ConfigSetting{
			types.SettingToken: {Value: "same-token", Changed: true},
		}, nil, analytics.TriggerSourceTest)
	})

	t.Run("empty token does not trigger refresh", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLdx := mock_command.NewMockLdxSyncService(ctrl)
		originalService := di.LdxSyncService()
		di.SetLdxSyncService(mockLdx)
		defer di.SetLdxSyncService(originalService)

		folderPath := types.FilePath(t.TempDir())
		workspaceutil.SetupWorkspace(t, c, folderPath)

		c.SetToken("existing-token")

		mockLdx.EXPECT().
			RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Times(0)

		UpdateSettings(c, map[string]*types.ConfigSetting{
			types.SettingToken: {Value: "", Changed: true},
		}, nil, analytics.TriggerSourceTest)
	})

	t.Run("no workspace folders skips refresh", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLdx := mock_command.NewMockLdxSyncService(ctrl)
		originalService := di.LdxSyncService()
		di.SetLdxSyncService(mockLdx)
		defer di.SetLdxSyncService(originalService)

		c.SetToken("old-token")

		mockLdx.EXPECT().
			RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Times(0)

		UpdateSettings(c, map[string]*types.ConfigSetting{
			types.SettingToken: {Value: "new-token", Changed: true},
		}, nil, analytics.TriggerSourceTest)
	})
}

func Test_UpdateSettings_BlankOrganizationResetsToDefault_Integration(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set to a specific org first
	initialOrgId := "00000000-0000-0000-0000-000000000001"
	config.SetOrganization(c.Engine().GetConfiguration(), initialOrgId)
	require.Equal(t, initialOrgId, c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION), "org should be set to the value we just set it to")

	// Set to empty string to reset to the user's preferred default org they defined in the web UI.
	UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingOrganization: {Value: "", Changed: true}}, nil, analytics.TriggerSourceTest)

	// Verify it's not the initial org or empty string.
	actualOrgAfterBlank := c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION)
	assert.NotEqual(t, initialOrgId, actualOrgAfterBlank, "org should have changed from initial value")
	assert.NotEmpty(t, actualOrgAfterBlank, "org should have resolved to the user's preferred default org they defined in the web UI")

	// Verify it's a valid UUID (preferred orgs are always UUIDs).
	_, err := uuid.Parse(actualOrgAfterBlank)
	assert.NoError(t, err, "resolved org should be a valid UUID")
}

func Test_UpdateSettings_WhitespaceOrganizationResetsToDefault_Integration(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set to a specific org first
	initialOrgId := "00000000-0000-0000-0000-000000000001"
	config.SetOrganization(c.Engine().GetConfiguration(), initialOrgId)
	require.Equal(t, initialOrgId, c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION), "org should be set to the value we just set it to")

	// Set to whitespace to reset to the user's preferred default org they defined in the web UI.
	// Whitespace should be trimmed to empty string.
	UpdateSettings(c, map[string]*types.ConfigSetting{types.SettingOrganization: {Value: " ", Changed: true}}, nil, analytics.TriggerSourceTest)

	// Verify it's not the initial org or empty string.
	actualOrgAfterWhitespace := c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION)
	assert.NotEqual(t, initialOrgId, actualOrgAfterWhitespace, "org should have changed from initial value")
	assert.NotEmpty(t, actualOrgAfterWhitespace, "org should have resolved to the user's preferred default org they defined in the web UI")

	// Verify it's a valid UUID (preferred orgs are always UUIDs).
	_, err := uuid.Parse(actualOrgAfterWhitespace)
	assert.NoError(t, err, "resolved org should be a valid UUID")
}

// Common test setup for updateFolderConfig tests
type folderConfigTestSetup struct {
	t            *testing.T
	c            *config.Config
	engineConfig configuration.Configuration
	logger       *zerolog.Logger
	folderPath   types.FilePath
}

func setupFolderConfigTest(t *testing.T) *folderConfigTestSetup {
	t.Helper()
	c := testutil.UnitTest(t)
	di.TestInit(t)

	engineConfig := c.Engine().GetConfiguration()

	// Register mock default value functions for org config to avoid API calls in tests
	engineConfig.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction("test-default-org-uuid"))
	engineConfig.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction("test-default-org-slug"))

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	require.NoError(t, err)

	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath)

	logger := c.Logger()

	return &folderConfigTestSetup{
		t:            t,
		c:            c,
		engineConfig: engineConfig,
		logger:       logger,
		folderPath:   folderPath,
	}
}

func (s *folderConfigTestSetup) createStoredConfig(org string, userSet bool) {
	storedConfig := &types.FolderConfig{FolderPath: s.folderPath}
	types.SetPreferredOrgAndOrgSetByUser(s.engineConfig, s.folderPath, org, userSet)
	err := storedconfig.UpdateFolderConfig(s.engineConfig, storedConfig, s.logger)
	require.NoError(s.t, err)
}

func (s *folderConfigTestSetup) getUpdatedConfig() *types.FolderConfig {
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(s.engineConfig, s.folderPath, s.logger)
	require.NoError(s.t, err)
	updatedConfig.SetConf(s.engineConfig)
	return updatedConfig
}

// setupLdxSyncReturnsDifferentOrg sets up the test scenario where
// a config has LDX-Sync return a different organization
func (s *folderConfigTestSetup) setupLdxSyncReturnsDifferentOrg() {
	s.createStoredConfig("initial-org", false)
	config.SetOrganization(s.c.Engine().GetConfiguration(), "global-org-id")
}

// setupConfigUserSetButInheritingFromBlank sets up the test scenario where
// a config was previously user-set but now inherits from blank global
func (s *folderConfigTestSetup) setupConfigUserSetButInheritingFromBlank() {
	s.createStoredConfig("", true)
	config.SetOrganization(s.c.Engine().GetConfiguration(), "")
}

func Test_updateFolderConfig_UserSetOrg_PreservedOnUpdate(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	require.NoError(t, err)

	// Setup stored config with user-set org
	engineConfig := c.Engine().GetConfiguration()
	logger := c.Logger()
	storedConfig := &types.FolderConfig{FolderPath: folderPath}
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath, "user-org-id", true)
	err = storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	config.SetOrganization(c.Engine().GetConfiguration(), "global-org-id")

	// Call UpdateSettings with the folder config and global org
	userOrgID := "user-org-id"
	settingsMap := map[string]*types.ConfigSetting{types.SettingOrganization: {Value: "global-org-id", Changed: true}}
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: userOrgID},
			},
		},
	}
	UpdateSettings(c, settingsMap, folderConfigs, analytics.TriggerSourceTest)

	// Verify the org was kept by reading directly from configuration
	snap := types.ReadFolderConfigSnapshot(engineConfig, folderPath)
	assert.Equal(t, "user-org-id", snap.PreferredOrg, "PreferredOrg should remain as user-set value")
}

func Test_updateFolderConfig_EmptyOrgSent_InheritsFromGlobal(t *testing.T) {
	setup := setupFolderConfigTest(t)

	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: ""},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false for auto-inherited org")
	assert.Equal(t, setup.c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION), updatedConfig.PreferredOrg(), "empty org should inherit from global")
}

func Test_updateFolderConfig_EmptyStoredOrg_InheritsFromGlobal(t *testing.T) {
	setup := setupFolderConfigTest(t)
	setup.createStoredConfig("", false)

	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: ""},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false when inheriting from global")
	assert.Equal(t, setup.c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION), updatedConfig.PreferredOrg(), "PreferredOrg should inherit from global organization")
}

func Test_updateFolderConfig_LdxSyncReturnsDifferentOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)
	setup.setupLdxSyncReturnsDifferentOrg()

	initialOrg := "initial-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: initialOrg},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false when inheriting from LDX-Sync")
}

func Test_updateFolderConfig_UserSetButInheritingFromBlankGlobal(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup the test scenario
	setup.setupConfigUserSetButInheritingFromBlank()

	// Call UpdateSettings with empty org settings
	emptyOrg := ""
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: emptyOrg},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	// Verify: should attempt to resolve from LDX-Sync because inheriting from blank global
	// This test specifically checks the case where both folder and global orgs are empty
	updatedConfig := setup.getUpdatedConfig()
	// When LDX-Sync is called, OrgSetByUser behavior depends on the result
	assert.Empty(t, updatedConfig.PreferredOrg(), "PreferredOrg should remain empty when inheriting from blank global")
}

// Test that UpdateFolderConfigOrg is skipped when config is unchanged and global org hasn't changed
func Test_updateFolderConfig_SkipsUpdateWhenConfigUnchanged(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	require.NoError(t, err)

	// Setup stored config
	engineConfig := c.Engine().GetConfiguration()
	logger := c.Logger()
	storedConfig := &types.FolderConfig{FolderPath: folderPath}
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath, "test-org", true)
	err = storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	config.SetOrganization(c.Engine().GetConfiguration(), "test-org")

	// Call UpdateSettings with exact same config and same global org
	// DeepEqual should return true, so UpdateFolderConfigOrg should be skipped
	testOrg := "test-org"
	settingsMap := map[string]*types.ConfigSetting{types.SettingOrganization: {Value: "test-org", Changed: true}}
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: testOrg},
			},
		},
	}
	UpdateSettings(c, settingsMap, folderConfigs, analytics.TriggerSourceTest)

	// Verify config remains unchanged by reading directly from configuration
	snap := types.ReadFolderConfigSnapshot(engineConfig, folderPath)
	assert.Equal(t, "test-org", snap.PreferredOrg)
	assert.True(t, snap.OrgSetByUser, "Should remain true since UpdateFolderConfigOrg was skipped")
}

func Test_updateFolderConfig_HandlesNilStoredConfig(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	// Use a non-existent path that might return nil
	folderPath := types.FilePath("/non/existent/path")

	config.SetOrganization(c.Engine().GetConfiguration(), "test-org")

	// Call UpdateSettings with a folder that doesn't exist
	testOrg := "test-org"
	settingsMap := map[string]*types.ConfigSetting{types.SettingOrganization: {Value: "test-org", Changed: true}}
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: testOrg},
			},
		},
	}

	// Should not panic and should handle nil gracefully
	UpdateSettings(c, settingsMap, folderConfigs, analytics.TriggerSourceTest)
	// If we get here without panic, the nil check worked
}

func Test_InitializeSettings(t *testing.T) {
	di.TestInit(t)

	t.Run("device ID is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)
		deviceId := "test-device-id"

		InitializeSettings(c, types.InitializationOptions{DeviceId: deviceId})

		assert.Equal(t, deviceId, c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingDeviceId)))
	})

	t.Run("device ID is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)
		deviceId := c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingDeviceId))

		InitializeSettings(c, types.InitializationOptions{})

		assert.Equal(t, deviceId, c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingDeviceId)))
	})

	t.Run("activateSnykCodeSecurity enables SnykCode via OR on init", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}},
		})

		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)), "snyk_code_enabled should enable Snyk Code on init")
	})
	t.Run("activateSnykCodeSecurity not passed does not enable SnykCode on init", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, types.InitializationOptions{})

		assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))
	})

	t.Run("custom path configuration", func(t *testing.T) {
		c := testutil.UnitTest(t)

		first := "first"
		second := "second"

		upperCasePathKey := "PATH"
		caseSensitivePathKey := "Path"
		t.Setenv(caseSensitivePathKey, "something_meaningful")

		// Path is init-only; use InitializeSettings
		InitializeSettings(c, types.InitializationOptions{Path: first})
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), first+string(os.PathListSeparator)))

		InitializeSettings(c, types.InitializationOptions{Path: second})
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), second+string(os.PathListSeparator)))
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), first))

		// reset path and set auth method
		InitializeSettings(c, types.InitializationOptions{
			Path:     "",
			Settings: map[string]*types.ConfigSetting{types.SettingAuthenticationMethod: {Value: "token", Changed: true}},
		})
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), second))

		assert.True(t, keyFoundInEnv(upperCasePathKey))
		assert.False(t, keyFoundInEnv(caseSensitivePathKey))
	})
}

// Test: Mainly tests deleting AutoDeterminedOrg does not forget it.
func Test_updateFolderConfig_AutoMode_EmptyOrg_InheritsFromGlobal(t *testing.T) {
	setup := setupFolderConfigTest(t)

	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: ""},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false in auto mode")
	assert.Equal(t, setup.c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION), updatedConfig.PreferredOrg(), "PreferredOrg should inherit from global")
}

func Test_updateFolderConfig_UserSendsNewOrg_SetsOrgByUser(t *testing.T) {
	setup := setupFolderConfigTest(t)

	differentOrg := "different-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: differentOrg},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "different-org", updatedConfig.PreferredOrg(), "PreferredOrg should be the new org")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be true when user sends non-empty org")
}

func Test_updateFolderConfig_OrgChange_TriggersLdxSyncRefresh(t *testing.T) {
	setup := setupFolderConfigTest(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLdxSyncService := mock_command.NewMockLdxSyncService(ctrl)
	originalService := di.LdxSyncService()
	di.SetLdxSyncService(mockLdxSyncService)
	defer di.SetLdxSyncService(originalService)

	setup.createStoredConfig("initial-org", true)

	folders := setup.c.Workspace().Folders()
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), setup.c, gomock.Eq(folders), gomock.Any()).
		Times(1)

	cache := setup.c.GetLdxSyncOrgConfigCache()
	cache.SetFolderOrg(setup.folderPath, "auto-determined-org")

	newUserOrg := "new-user-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: newUserOrg},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "new-user-org", updatedConfig.PreferredOrg(), "PreferredOrg should be updated")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be true after org change")
}

func Test_updateFolderConfig_StoredUserOrg_PreservedOnUpdate(t *testing.T) {
	setup := setupFolderConfigTest(t)

	setup.createStoredConfig("user-chosen-org", true)
	config.SetOrganization(setup.c.Engine().GetConfiguration(), "global-org-id")

	userChosenOrg := "user-chosen-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: userChosenOrg},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "user-chosen-org", updatedConfig.PreferredOrg(), "User-set org should be preserved")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should remain true")
}

// Test: AutoDeterminedOrg is missing and needs to be set
// When org settings change, updateFolderConfigOrg is called which sets AutoDeterminedOrg
func Test_updateFolderConfig_MissingAutoDeterminedOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config WITHOUT AutoDeterminedOrg (simulating old config)
	engineConfig := setup.c.Engine().GetConfiguration()
	storedConfig := &types.FolderConfig{FolderPath: setup.folderPath}
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, setup.folderPath, "test-org", true)
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, setup.logger)
	require.NoError(setup.t, err)

	config.SetOrganization(setup.c.Engine().GetConfiguration(), "global-org-id")

	// Call UpdateSettings with DIFFERENT org to trigger updateFolderConfigOrg
	differentTestOrg := "different-test-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: differentTestOrg},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	// Verify: AutoDeterminedOrg remains empty when LDX-Sync cache is empty
	// AutoDeterminedOrg should only contain what LDX-Sync determined, not a fallback
	// Fallback to global org happens at the point of use (in FolderOrganization)
	updatedConfig := setup.getUpdatedConfig()
	assert.Empty(t, updatedConfig.AutoDeterminedOrg(), "AutoDeterminedOrg should remain empty when LDX-Sync cache is empty")
}

func Test_updateFolderConfig_SwitchFromAutoToManualOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	userManualOrg := "user-manual-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: userManualOrg},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "user-manual-org", updatedConfig.PreferredOrg(), "PreferredOrg should be set to user choice")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be true after user sets org")
}

func Test_updateFolderConfig_Unauthenticated_UserSetsPreferredOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	engineConfig := c.Engine().GetConfiguration()
	folderPath := types.FilePath(t.TempDir())

	storedConfig := &types.FolderConfig{
		FolderPath: folderPath,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, c.Logger())
	require.NoError(t, err)

	config.SetOrganization(c.Engine().GetConfiguration(), "")

	userChosenOrg := "user-chosen-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: userChosenOrg},
			},
		},
	}
	UpdateSettings(c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, c.Logger())
	require.NoError(t, err)
	updatedConfig.SetConf(engineConfig)
	assert.Equal(t, "user-chosen-org", updatedConfig.PreferredOrg(), "PreferredOrg should be set")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be true when user chose org")
}

func Test_updateFolderConfig_ProcessesLspFolderConfigUpdates(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config
	setup.createStoredConfig("test-org", true)

	// Call UpdateSettings with LspFolderConfig updates (PATCH semantics)
	// Changed=true with Value indicates setting the value
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: false, Changed: true},
				types.SettingScanNetNew:    {Value: true, Changed: true},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	// Verify: UserOverrides should be set in stored config
	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic))
	assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanNetNew))
}

// FC-105: UpdateSettings correctly processes new map format with folder configs
func Test_FC105_WriteSettings_OldFormat_ProcessesSettingsStruct(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	folderPath := types.FilePath(t.TempDir())
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath)

	settingsMap := map[string]*types.ConfigSetting{
		types.SettingSnykCodeEnabled: {Value: true, Changed: true},
		types.SettingApiEndpoint:     {Value: "https://api.fc105.snyk.io", Changed: true},
	}
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: "folder-org-fc105"},
			},
		},
	}

	UpdateSettings(c, settingsMap, folderConfigs, analytics.TriggerSourceTest)

	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)), "old format ActivateSnykCode should be applied")
	assert.Equal(t, "https://api.fc105.snyk.io", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingApiEndpoint)))

	engineConfig := c.Engine().GetConfiguration()
	snap := types.ReadFolderConfigSnapshot(engineConfig, folderPath)
	assert.Equal(t, "folder-org-fc105", snap.PreferredOrg, "FolderConfigs should be processed via UpdateSettings")
}

// FC-106: writeSettings correctly processes new map[string]*LocalConfigField format (per-folder Settings map)
func Test_FC106_WriteSettings_NewFormat_ProcessesFolderConfigSettingsMap(t *testing.T) {
	setup := setupFolderConfigTest(t)
	setup.createStoredConfig("test-org", true)

	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: false, Changed: true},
				types.SettingBaseBranch:    {Value: "develop"},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic))
	scanAutoKey := configuration.UserFolderKey(string(types.PathKey(setup.folderPath)), types.SettingScanAutomatic)
	scanAutoVal := setup.engineConfig.Get(scanAutoKey)
	lf, ok := scanAutoVal.(*configuration.LocalConfigField)
	require.True(t, ok && lf != nil)
	assert.Equal(t, false, lf.Value)
	assert.Equal(t, "develop", updatedConfig.BaseBranch())
}

// Test that processSingleLspFolderConfig sets fc.conf before ApplyLspUpdate, so SetUserOverride
// dual-writes to configuration UserFolderKey. Without this, fc.conf would be nil and the prefix keys
// would never be written when the user sets overrides via the IDE.
func Test_updateFolderConfig_DualWritesUserOverride(t *testing.T) {
	setup := setupFolderConfigTest(t)
	setup.createStoredConfig("test-org", true)

	// Call UpdateSettings with incoming LspFolderConfig that sets a user override (ScanAutomatic)
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: false, Changed: true},
			},
		},
	}
	UpdateSettings(setup.c, nil, folderConfigs, analytics.TriggerSourceTest)

	// Verify: UserFolderKey prefix key must be written (dual-write from SetUserOverride)
	// processSingleLspFolderConfig must call folderConfig.SetConf before ApplyLspUpdate
	prefixKeyConfig := setup.c.Engine().GetConfiguration()
	normalizedPath := string(types.PathKey(setup.folderPath))
	scanAutoKey := configuration.UserFolderKey(normalizedPath, types.SettingScanAutomatic)
	require.True(t, prefixKeyConfig.IsSet(scanAutoKey),
		"UserFolderKey should be set in configuration when processSingleLspFolderConfig applies user override (fc.conf must be set before ApplyLspUpdate)")
}

func Test_validateLockedFields_UsesNewOrgPolicyOnOrgSwitch(t *testing.T) {
	t.Run("rejects locked settings from new org when PreferredOrg changes simultaneously", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		// Folder currently belongs to org-A (no locks)
		setup.createStoredConfig("org-a", true)

		// Set up LDX-Sync cache: org-B locks SnykCodeEnabled
		cache := setup.c.GetLdxSyncOrgConfigCache()
		orgConfigB := types.NewLDXSyncOrgConfig("org-b")
		orgConfigB.SetField(types.SettingSnykCodeEnabled, true, true, "group") // locked
		cache.SetOrgConfig(orgConfigB)

		// Set up a real ConfigResolver so validateLockedFields can use it.
		// Set prefixKeyConf only (nil prefixKeyResolver) so getEffectiveOrg reads from configuration
		// while IsLocked uses ldxSyncCache for org-scoped locks.
		resolver := types.NewConfigResolver(cache, setup.c, setup.logger)
		prefixKeyConf := setup.c.Engine().GetConfiguration()
		resolver.SetPrefixKeyResolver(nil, prefixKeyConf)
		di.SetConfigResolver(resolver)

		// Incoming update: switch to org-B AND change SnykCodeEnabled (which org-B locks)
		newOrg := "org-b"
		incoming := types.LspFolderConfig{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg:    {Value: newOrg},
				types.SettingSnykCodeEnabled: {Value: false, Changed: true},
				types.SettingScanAutomatic:   {Value: true, Changed: true}, // not locked
			},
		}

		folderConfig := setup.getUpdatedConfig()

		rejected := validateLockedFields(setup.c, folderConfig, &incoming, setup.logger)

		assert.True(t, rejected, "should reject changes to settings locked by the new org")
		// SnykCodeEnabled should have been cleared (locked by org-B)
		assert.Nil(t, incoming.Settings[types.SettingSnykCodeEnabled], "locked setting should be cleared from incoming")
		// ScanAutomatic should still be present (not locked)
		assert.NotNil(t, incoming.Settings[types.SettingScanAutomatic], "non-locked setting should remain in incoming")
	})

	t.Run("allows settings when old org has locks but new org does not", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		// Folder currently belongs to org-A which locks SnykCodeEnabled
		setup.createStoredConfig("org-a", true)

		cache := setup.c.GetLdxSyncOrgConfigCache()
		orgConfigA := types.NewLDXSyncOrgConfig("org-a")
		orgConfigA.SetField(types.SettingSnykCodeEnabled, true, true, "group") // locked
		cache.SetOrgConfig(orgConfigA)
		// org-B has no locks

		resolver := types.NewConfigResolver(cache, setup.c, setup.logger)
		prefixKeyConf := setup.c.Engine().GetConfiguration()
		resolver.SetPrefixKeyResolver(nil, prefixKeyConf)
		di.SetConfigResolver(resolver)

		// Incoming update: switch to org-B AND change SnykCodeEnabled
		newOrg := "org-b"
		incoming := types.LspFolderConfig{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg:    {Value: newOrg},
				types.SettingSnykCodeEnabled: {Value: false, Changed: true},
			},
		}

		folderConfig := setup.getUpdatedConfig()

		rejected := validateLockedFields(setup.c, folderConfig, &incoming, setup.logger)

		assert.False(t, rejected, "should allow changes when new org has no locks")
		assert.NotNil(t, incoming.Settings[types.SettingSnykCodeEnabled], "setting should remain since new org doesn't lock it")
	})
}

func Test_batchClearOrgScopedOverridesOnGlobalChange(t *testing.T) {
	t.Run("clears existing overrides for changed settings", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true)

		// Pre-set some folder-level overrides
		storedCfg := setup.getUpdatedConfig()
		fp := string(types.PathKey(setup.folderPath))
		setup.engineConfig.Set(configuration.UserFolderKey(fp, types.SettingScanAutomatic), &configuration.LocalConfigField{Value: false, Changed: true})
		setup.engineConfig.Set(configuration.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configuration.LocalConfigField{Value: false, Changed: true})
		setup.engineConfig.Set(configuration.UserFolderKey(fp, types.SettingSnykOssEnabled), &configuration.LocalConfigField{Value: true, Changed: true})
		err := storedconfig.UpdateFolderConfig(setup.c.Engine().GetConfiguration(), storedCfg, setup.c.Logger())
		require.NoError(t, err)

		// Global change for ScanAutomatic and SnykCodeEnabled
		pending := map[string]any{
			types.SettingScanAutomatic:   true,
			types.SettingSnykCodeEnabled: true,
		}

		batchClearOrgScopedOverridesOnGlobalChange(setup.c, pending)

		updatedConfig := setup.getUpdatedConfig()
		// Changed settings should have their overrides cleared
		assert.False(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic), "override should be cleared")
		assert.False(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingSnykCodeEnabled), "override should be cleared")
		// Unchanged setting should still have its override
		assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingSnykOssEnabled), "unrelated override should be preserved")
	})

	t.Run("skips locked settings per folder", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true)

		// Pre-set overrides
		storedCfg := setup.getUpdatedConfig()
		fp := string(types.PathKey(setup.folderPath))
		setup.engineConfig.Set(configuration.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configuration.LocalConfigField{Value: false, Changed: true})
		setup.engineConfig.Set(configuration.UserFolderKey(fp, types.SettingScanAutomatic), &configuration.LocalConfigField{Value: false, Changed: true})
		err := storedconfig.UpdateFolderConfig(setup.c.Engine().GetConfiguration(), storedCfg, setup.c.Logger())
		require.NoError(t, err)

		// Set up LDX-Sync cache with a locked field
		cache := setup.c.GetLdxSyncOrgConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("test-org")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, "group") // locked
		cache.SetOrgConfig(orgConfig)
		cache.SetFolderOrg(setup.folderPath, "test-org")

		pending := map[string]any{
			types.SettingSnykCodeEnabled: true, // locked — override should NOT be cleared
			types.SettingScanAutomatic:   true, // not locked — override should be cleared
		}

		batchClearOrgScopedOverridesOnGlobalChange(setup.c, pending)

		updatedConfig := setup.getUpdatedConfig()
		// Locked setting override should be preserved
		assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingSnykCodeEnabled), "locked setting override should be preserved")
		// Non-locked setting override should be cleared
		assert.False(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic), "non-locked override should be cleared")
	})

	t.Run("filters out non-org-scoped settings", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true)

		// Pre-set an override for an org-scoped setting
		storedCfg := setup.getUpdatedConfig()
		fp := string(types.PathKey(setup.folderPath))
		setup.engineConfig.Set(configuration.UserFolderKey(fp, types.SettingScanAutomatic), &configuration.LocalConfigField{Value: false, Changed: true})
		err := storedconfig.UpdateFolderConfig(setup.c.Engine().GetConfiguration(), storedCfg, setup.c.Logger())
		require.NoError(t, err)

		pending := map[string]any{
			types.SettingApiEndpoint:   "https://api.snyk.io", // machine-scoped, should be ignored
			types.SettingScanAutomatic: true,                  // org-scoped, override should be cleared
		}

		batchClearOrgScopedOverridesOnGlobalChange(setup.c, pending)

		updatedConfig := setup.getUpdatedConfig()
		assert.False(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic), "org-scoped override should be cleared")
	})

	t.Run("does nothing for empty pending map", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true)

		// Pre-set an override
		storedCfg := setup.getUpdatedConfig()
		fp := string(types.PathKey(setup.folderPath))
		setup.engineConfig.Set(configuration.UserFolderKey(fp, types.SettingScanAutomatic), &configuration.LocalConfigField{Value: false, Changed: true})
		err := storedconfig.UpdateFolderConfig(setup.c.Engine().GetConfiguration(), storedCfg, setup.c.Logger())
		require.NoError(t, err)

		// Should not panic or error, and should not clear anything
		batchClearOrgScopedOverridesOnGlobalChange(setup.c, map[string]any{})
		batchClearOrgScopedOverridesOnGlobalChange(setup.c, nil)

		updatedConfig := setup.getUpdatedConfig()
		assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic), "override should be preserved when pending is empty")
	})

	t.Run("does nothing when no overrides exist", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true)

		pending := map[string]any{
			types.SettingScanAutomatic: true,
		}

		// Should not panic or error when no overrides exist
		batchClearOrgScopedOverridesOnGlobalChange(setup.c, pending)

		updatedConfig := setup.getUpdatedConfig()
		assert.False(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic))
	})

	// clearFolderOverridesForSettings must Unset UserFolderKey when clearing overrides,
	// so ConfigResolver returns the new global value instead of stale prefix keys.
	t.Run("unsets UserFolderKey when clearing folder overrides", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true)

		// Set folder override via configuration (dual-writes to UserFolderKey)
		storedCfg := setup.getUpdatedConfig()
		prefixKeyConfig := setup.c.Engine().GetConfiguration()
		fp := string(types.PathKey(setup.folderPath))
		prefixKeyConfig.Set(configuration.UserFolderKey(fp, types.SettingScanAutomatic), &configuration.LocalConfigField{Value: false, Changed: true})
		prefixKeyConfig.Set(configuration.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configuration.LocalConfigField{Value: false, Changed: true})
		err := storedconfig.UpdateFolderConfig(setup.c.Engine().GetConfiguration(), storedCfg, setup.c.Logger())
		require.NoError(t, err)

		// Verify UserFolderKey is set in configuration (simulating dual-write from SetUserOverride)
		normalizedPath := string(types.PathKey(setup.folderPath))
		scanAutoKey := configuration.UserFolderKey(normalizedPath, types.SettingScanAutomatic)
		snykCodeKey := configuration.UserFolderKey(normalizedPath, types.SettingSnykCodeEnabled)
		require.True(t, prefixKeyConfig.IsSet(scanAutoKey), "UserFolderKey should be set before clear")
		require.True(t, prefixKeyConfig.IsSet(snykCodeKey), "UserFolderKey should be set before clear")

		// Global change triggers clearFolderOverridesForSettings
		pending := map[string]any{
			types.SettingScanAutomatic:   true,
			types.SettingSnykCodeEnabled: true,
		}
		batchClearOrgScopedOverridesOnGlobalChange(setup.c, pending)

		// UserOverrides must be cleared
		updatedConfig := setup.getUpdatedConfig()
		assert.False(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic), "override should be cleared")
		assert.False(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingSnykCodeEnabled), "override should be cleared")

		// UserFolderKey must be unset so ConfigResolver returns global value, not stale override
		val1 := prefixKeyConfig.Get(scanAutoKey)
		lf1, isLocalConfigField1 := val1.(*configuration.LocalConfigField)
		assert.False(t, isLocalConfigField1 && lf1 != nil && lf1.Changed,
			"UserFolderKey for ScanAutomatic should be cleared after clearFolderOverridesForSettings")
		val2 := prefixKeyConfig.Get(snykCodeKey)
		lf2, isLocalConfigField2 := val2.(*configuration.LocalConfigField)
		assert.False(t, isLocalConfigField2 && lf2 != nil && lf2.Changed,
			"UserFolderKey for SnykCodeEnabled should be cleared after clearFolderOverridesForSettings")
	})
}
