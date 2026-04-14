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
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"

	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/internal/folderconfig"
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
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)
	loc, _ := setupServer(t, engine, tokenService)

	// Wait for default environment to be ready before testing PATH updates
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := types.WaitForDefaultEnv(ctx, engine.GetConfiguration())
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
	params := types.DidChangeConfigurationParams{Settings: types.LspConfigurationParam{Settings: sampleSettings}}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	conf := engine.GetConfiguration()
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))
	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingCliInsecure)))
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	ossParams, ok := engine.GetConfiguration().Get(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"--all-projects", "-d"}, ossParams)
	assert.Equal(t, "https://api.fake.snyk.io", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))
	assert.Equal(t, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)), conf.GetString(configuration.API_URL))
	assert.Equal(t, "b", os.Getenv("a"))
	assert.Equal(t, "d", os.Getenv("c"))
	assert.True(t, strings.Contains(os.Getenv("PATH"), "addPath"))
	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSendErrorReports)))
	assert.Equal(t, "token", config.GetToken(engine.GetConfiguration()))
	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingEnableSnykLearnCodeActions)))
}

// Test_WorkspaceDidChangeConfiguration_LspEnvelope verifies that the handler correctly
// processes settings wrapped in the standard LSP envelope: {"settings": {"settings": {...}, "folderConfigs": [...]}}
// LSP4J (IntelliJ) wraps our DidChangeConfigurationParams inside the spec's single "settings" field.
func Test_WorkspaceDidChangeConfiguration_LspEnvelope(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)
	loc, _ := setupServer(t, engine, tokenService)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := types.WaitForDefaultEnv(ctx, engine.GetConfiguration())
	if err != nil {
		t.Fatal(err, "error waiting for default environment")
	}

	_, _ = loc.Client.Call(t.Context(), "initialize", types.InitializeParams{
		Capabilities: types.ClientCapabilities{},
		InitializationOptions: types.InitializationOptions{
			Path: "addPath",
		},
	})

	// Send settings in the standard LSP format: {"settings": {"settings": {...}, "folderConfigs": [...]}}
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingSnykOssEnabled:  {Value: false, Changed: true},
				types.SettingSnykCodeEnabled: {Value: false, Changed: true},
				types.SettingSnykIacEnabled:  {Value: false, Changed: true},
				types.SettingToken:           {Value: "envelope-token", Changed: true},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	require.NoError(t, err)

	conf := engine.GetConfiguration()
	assert.False(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "Code should be disabled via LSP envelope")
	assert.False(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)), "OSS should be disabled via LSP envelope")
	assert.False(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)), "IAC should be disabled via LSP envelope")
	assert.Equal(t, "envelope-token", config.GetToken(conf), "Token should be set via LSP envelope")
}

func Test_WorkspaceDidChangeConfiguration_Pull(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupCustomServer(t, engine, tokenService, callBackMock)

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

	params := types.DidChangeConfigurationParams{Settings: types.LspConfigurationParam{Settings: map[string]*types.ConfigSetting{}}}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}
	assert.NoError(t, err)

	conf := engine.GetConfiguration()
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))
	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingCliInsecure)))
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	ossParams, ok := engine.GetConfiguration().Get(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"--all-projects", "-d"}, ossParams)
	assert.Equal(t, "https://api.fake.snyk.io", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))
	assert.Equal(t, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)), conf.GetString(configuration.API_URL))
	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSendErrorReports)))
	assert.Equal(t, "token", config.GetToken(engine.GetConfiguration()))
	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingEnableSnykLearnCodeActions)))
}

func callBackMock(_ context.Context, request *jrpc2.Request) (any, error) {
	if request.Method() == "workspace/configuration" {
		return []types.DidChangeConfigurationParams{{Settings: types.LspConfigurationParam{Settings: sampleSettings}}}, nil
	}
	return nil, nil
}

func Test_WorkspaceDidChangeConfiguration_PullNoCapability(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupCustomServer(t, engine, tokenService, callBackMock)

	params := types.DidChangeConfigurationParams{Settings: types.LspConfigurationParam{Settings: map[string]*types.ConfigSetting{}}}
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
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService)

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
			types.SettingSeverityFilterCritical:       {Value: false, Changed: true},
			types.SettingSeverityFilterHigh:           {Value: true, Changed: true},
			types.SettingSeverityFilterMedium:         {Value: false, Changed: true},
			types.SettingSeverityFilterLow:            {Value: true, Changed: true},
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
		InitializeSettings(engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{
			Path:           "addPath",
			TrustedFolders: []string{"trustedPath1", "trustedPath2"},
			OsPlatform:     "windows",
			OsArch:         "amd64",
			RuntimeName:    "java",
			RuntimeVersion: "1.8.0_275",
			HoverVerbosity: &hoverVerbosity,
			OutputFormat:   &outputFormat,
		})
		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
		assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))
		assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))
		assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingCliInsecure)))
		ossParams, ok := engine.GetConfiguration().Get(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string)
		require.True(t, ok)
		assert.Equal(t, []string{"--all-projects", "-d"}, ossParams)
		assert.Equal(t, "https://api.snyk.io", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))
		assert.Equal(t, "b", os.Getenv("a"))
		assert.Equal(t, "d", os.Getenv("c"))
		assert.True(t, strings.HasPrefix(os.Getenv("PATH"), "addPath"+string(os.PathListSeparator)))
		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSendErrorReports)))
		// Organization is set globally but may be cleared at folder level by LDX-Sync logic
		// when it matches the global org and is not the default
		assert.Equal(t, expectedOrgId, engine.GetConfiguration().GetString(configuration.ORGANIZATION))
		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload)))
		assert.Equal(t, filepath.Join(cliDir, "cli"), engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingCliPath)))
		assert.Equal(t, nonDefaultSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))
		assert.Equal(t, nonDefaultIssueViewOptions, config.GetIssueViewOptions(engine.GetConfiguration()))
		tf, _ := engine.GetConfiguration().Get(configresolver.UserGlobalKey(types.SettingTrustedFolders)).([]types.FilePath)
		assert.Subset(t, []types.FilePath{"trustedPath1", "trustedPath2"}, tf)
		conf := engine.GetConfiguration()
		assert.Equal(t, "windows", conf.GetString(configresolver.UserGlobalKey(types.SettingOsPlatform)))
		assert.Equal(t, "amd64", conf.GetString(configresolver.UserGlobalKey(types.SettingOsArch)))
		assert.Equal(t, "java", conf.GetString(configresolver.UserGlobalKey(types.SettingRuntimeName)))
		assert.Equal(t, "1.8.0_275", conf.GetString(configresolver.UserGlobalKey(types.SettingRuntimeVersion)))
		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingScanAutomatic)))
		assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions)))
		assert.Equal(t, 1, engine.GetConfiguration().GetInt(configresolver.UserGlobalKey(types.SettingHoverVerbosity)))
		assert.Equal(t, "html", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingFormat)))

		folderConfig1 := config.GetFolderConfigFromEngine(engine, testutil.DefaultConfigResolver(engine), types.FilePath(tempDir1), engine.GetLogger())
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

		folderConfig2 := config.GetFolderConfigFromEngine(engine, testutil.DefaultConfigResolver(engine), types.FilePath(tempDir2), engine.GetLogger())
		assert.NotEmpty(t, folderConfig2.BaseBranch())
		assert.Empty(t, folderConfig2.AdditionalParameters())
		assert.Equal(t, expectedOrgId, folderConfig2.PreferredOrg(), "PreferredOrg should be set from global or LDX-Sync")

		assert.Eventually(t, func() bool { return config.GetToken(engine.GetConfiguration()) == "a fancy token" }, time.Second*5, time.Millisecond)
	})

	t.Run("hover defaults are set", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, 3, types.GetGlobalInt(engine.GetConfiguration(), types.SettingHoverVerbosity))
		assert.Equal(t, config.FormatMd, types.GetGlobalString(engine.GetConfiguration(), types.SettingFormat))
	})

	t.Run("incomplete env vars", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAdditionalEnvironment: {Value: "a=", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("empty env vars", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		varCount := len(os.Environ())

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAdditionalEnvironment: {Value: " ", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, varCount, len(os.Environ()))
	})

	t.Run("broken env variables", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAdditionalEnvironment: {Value: "a=; b", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Empty(t, os.Getenv("a"))
		assert.Empty(t, os.Getenv("b"))
		assert.Empty(t, os.Getenv(";"))
	})
	t.Run("trusted folders", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService)

		// Use platform-appropriate paths; TrustedFolders is init-only, use InitializeSettings
		path1 := filepath.Join("a", "b")
		path2 := filepath.Join("b", "c")
		InitializeSettings(engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{TrustedFolders: []string{path1, path2}})

		tf, _ := engine.GetConfiguration().Get(configresolver.UserGlobalKey(types.SettingTrustedFolders)).([]types.FilePath)
		assert.Contains(t, tf, types.FilePath(path1))
		assert.Contains(t, tf, types.FilePath(path2))
	})

	t.Run("manage binaries automatically", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		t.Run("true", func(t *testing.T) {
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload)))
		})
		t.Run("false", func(t *testing.T) {
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: false, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload)))
		})

		t.Run("invalid value does not update", func(t *testing.T) {
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: "dog", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload)))
		})
	})

	t.Run("activateSnykCodeSecurity enables SnykCode via OR", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "snyk_code_enabled should enable Snyk Code")
	})
	t.Run("activateSnykCode and activateSnykCodeSecurity are ORed", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "Should be enabled when snyk_code_enabled is true")
	})
	t.Run("activateSnykCode alone enables SnykCode", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	})
	t.Run("neither activateSnykCode nor activateSnykCodeSecurity disables SnykCode", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: false, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	})

	t.Run("activateSnykSecrets is passed", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykSecretsEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
	})
	t.Run("activateSnykSecrets false", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykSecretsEnabled: {Value: false, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
	})
	t.Run("activateSnykSecrets not passed does not update", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService)

		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
	})

	t.Run("severity filter", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(true, false, true, false)
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterCritical: {Value: true, Changed: true},
				types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
				types.SettingSeverityFilterMedium:   {Value: true, Changed: true},
				types.SettingSeverityFilterLow:      {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.Equal(t, mixedSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeSeverityFilter := types.NewSeverityFilter(false, false, false, false)
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterCritical: {Value: false, Changed: true},
				types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
				types.SettingSeverityFilterMedium:   {Value: false, Changed: true},
				types.SettingSeverityFilterLow:      {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.Equal(t, emptyLikeSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(false, false, true, false)
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterCritical: {Value: false, Changed: true},
				types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
				types.SettingSeverityFilterMedium:   {Value: true, Changed: true},
				types.SettingSeverityFilterLow:      {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
			assert.Equal(t, mixedSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))

			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
			assert.Equal(t, mixedSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))
		})
		t.Run("partial update preserves unchanged severities", func(t *testing.T) {
			// Set initial state: Critical=false, High=false, Medium=true, Low=false
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterCritical: {Value: false, Changed: true},
				types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
				types.SettingSeverityFilterMedium:   {Value: true, Changed: true},
				types.SettingSeverityFilterLow:      {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
			assert.Equal(t, types.NewSeverityFilter(false, false, true, false), config.GetFilterSeverity(engine.GetConfiguration()))

			// Partial update: only toggle High to true; omitted severities must be preserved
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterHigh: {Value: true, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			expected := types.NewSeverityFilter(false, true, true, false)
			assert.Equal(t, expected, config.GetFilterSeverity(engine.GetConfiguration()))
		})
	})

	t.Run("issue view options", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				types.SettingIssueViewIgnoredIssues: {Value: true, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.Equal(t, mixedIssueViewOptions, config.GetIssueViewOptions(engine.GetConfiguration()))
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeIssueViewOptions := types.NewIssueViewOptions(false, false)
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				types.SettingIssueViewIgnoredIssues: {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.Equal(t, emptyLikeIssueViewOptions, config.GetIssueViewOptions(engine.GetConfiguration()))
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				types.SettingIssueViewIgnoredIssues: {Value: true, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
			assert.Equal(t, mixedIssueViewOptions, config.GetIssueViewOptions(engine.GetConfiguration()))

			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
			assert.Equal(t, mixedIssueViewOptions, config.GetIssueViewOptions(engine.GetConfiguration()))
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
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLdx := mock_command.NewMockLdxSyncService(ctrl)
		originalService := di.LdxSyncService()
		di.SetLdxSyncService(mockLdx)
		defer di.SetLdxSyncService(originalService)

		folderPath := types.FilePath(t.TempDir())
		workspaceutil.SetupWorkspace(t, engine, folderPath)

		tokenService.SetToken(engine.GetConfiguration(), "old-token")

		folders := config.GetWorkspace(engine.GetConfiguration()).Folders()
		mockLdx.EXPECT().
			RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(folders), gomock.Any()).
			Times(1)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
			types.SettingToken: {Value: "new-token", Changed: true},
		}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
	})

	for _, tt := range []struct {
		name          string
		existingToken string
		newToken      string
	}{
		{"same token does not trigger refresh", "same-token", "same-token"},
		{"empty token does not trigger refresh", "existing-token", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			di.TestInit(t, engine, tokenService)

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockLdx := mock_command.NewMockLdxSyncService(ctrl)
			originalService := di.LdxSyncService()
			di.SetLdxSyncService(mockLdx)
			defer di.SetLdxSyncService(originalService)

			folderPath := types.FilePath(t.TempDir())
			workspaceutil.SetupWorkspace(t, engine, folderPath)

			tokenService.SetToken(engine.GetConfiguration(), tt.existingToken)

			mockLdx.EXPECT().
				RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Times(0)

			UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingToken: {Value: tt.newToken, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
		})
	}

	t.Run("no workspace folders skips refresh", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLdx := mock_command.NewMockLdxSyncService(ctrl)
		originalService := di.LdxSyncService()
		di.SetLdxSyncService(mockLdx)
		defer di.SetLdxSyncService(originalService)

		tokenService.SetToken(engine.GetConfiguration(), "old-token")

		mockLdx.EXPECT().
			RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Times(0)

		UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
			types.SettingToken: {Value: "new-token", Changed: true},
		}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
	})
}

func Test_UpdateSettings_BlankOrganizationResetsToDefault_Integration(t *testing.T) {
	engine := testutil.IntegTest(t)
	conf := engine.GetConfiguration()

	// Set to a specific org first
	initialOrgId := "00000000-0000-0000-0000-000000000001"
	config.SetOrganization(conf, initialOrgId)
	require.Equal(t, initialOrgId, conf.GetString(configuration.ORGANIZATION), "org should be set to the value we just set it to")

	// Set to empty string to reset to the user's preferred default org they defined in the web UI.
	UpdateSettings(conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingOrganization: {Value: "", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	// GAF's DefaultValueFunction for ORGANIZATION is synchronous: GetString blocks until the API call completes.
	actualOrg := conf.GetString(configuration.ORGANIZATION)
	assert.NotEqual(t, initialOrgId, actualOrg, "org should have changed from initial value")
	assert.NotEmpty(t, actualOrg, "org should have resolved to the user's preferred default org they defined in the web UI")
	_, err := uuid.Parse(actualOrg)
	assert.NoError(t, err, "resolved org should be a valid UUID")
}

func Test_UpdateSettings_WhitespaceOrganizationResetsToDefault_Integration(t *testing.T) {
	engine := testutil.IntegTest(t)
	conf := engine.GetConfiguration()

	// Set to a specific org first
	initialOrgId := "00000000-0000-0000-0000-000000000001"
	config.SetOrganization(conf, initialOrgId)
	require.Equal(t, initialOrgId, conf.GetString(configuration.ORGANIZATION), "org should be set to the value we just set it to")

	// Set to whitespace to reset to the user's preferred default org they defined in the web UI.
	// Whitespace should be trimmed to empty string.
	UpdateSettings(conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingOrganization: {Value: " ", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	// GAF's DefaultValueFunction for ORGANIZATION is synchronous: GetString blocks until the API call completes.
	actualOrg := conf.GetString(configuration.ORGANIZATION)
	assert.NotEqual(t, initialOrgId, actualOrg, "org should have changed from initial value")
	assert.NotEmpty(t, actualOrg, "org should have resolved to the user's preferred default org they defined in the web UI")
	_, err := uuid.Parse(actualOrg)
	assert.NoError(t, err, "resolved org should be a valid UUID")
}

// Common test setup for updateFolderConfig tests
type folderConfigTestSetup struct {
	t            *testing.T
	engine       workflow.Engine
	engineConfig configuration.Configuration
	logger       *zerolog.Logger
	folderPath   types.FilePath
}

func setupFolderConfigTest(t *testing.T) *folderConfigTestSetup {
	t.Helper()
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)

	engineConfig := engine.GetConfiguration()

	// Register mock default value functions for org config to avoid API calls in tests
	engineConfig.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction("test-default-org-uuid"))
	engineConfig.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction("test-default-org-slug"))

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	require.NoError(t, err)

	_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath)

	logger := engine.GetLogger()

	return &folderConfigTestSetup{
		t:            t,
		engine:       engine,
		engineConfig: engineConfig,
		logger:       logger,
		folderPath:   folderPath,
	}
}

func (s *folderConfigTestSetup) createStoredConfig(org string, userSet bool) {
	types.SetPreferredOrgAndOrgSetByUser(s.engineConfig, s.folderPath, org, userSet)
}

func (s *folderConfigTestSetup) getUpdatedConfig() *types.FolderConfig {
	updatedConfig, err := folderconfig.GetOrCreateFolderConfig(s.engineConfig, s.folderPath, s.logger)
	require.NoError(s.t, err)
	updatedConfig.ConfigResolver = types.NewMinimalConfigResolver(s.engineConfig)
	return updatedConfig
}

// setupLdxSyncReturnsDifferentOrg sets up the test scenario where
// a config has LDX-Sync return a different organization
func (s *folderConfigTestSetup) setupLdxSyncReturnsDifferentOrg() {
	s.createStoredConfig("initial-org", false)
	config.SetOrganization(s.engine.GetConfiguration(), "global-org-id")
}

// setupConfigUserSetButInheritingFromBlank sets up the test scenario where
// a config was previously user-set but now inherits from blank global
func (s *folderConfigTestSetup) setupConfigUserSetButInheritingFromBlank() {
	s.createStoredConfig("", true)
	config.SetOrganization(s.engine.GetConfiguration(), "")
}

func Test_updateFolderConfig_UserSetOrg_PreservedOnUpdate(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	require.NoError(t, err)

	// Setup folderConfig with user-set org
	engineConfig := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath, "user-org-id", true)

	config.SetOrganization(engine.GetConfiguration(), "global-org-id")

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
	UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false for auto-inherited org")
	assert.Equal(t, setup.engine.GetConfiguration().GetString(configuration.ORGANIZATION), updatedConfig.PreferredOrg(), "empty org should inherit from global")
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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false when inheriting from global")
	assert.Equal(t, setup.engine.GetConfiguration().GetString(configuration.ORGANIZATION), updatedConfig.PreferredOrg(), "PreferredOrg should inherit from global organization")
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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	// Verify: should attempt to resolve from LDX-Sync because inheriting from blank global
	// This test specifically checks the case where both folder and global orgs are empty
	updatedConfig := setup.getUpdatedConfig()
	// When LDX-Sync is called, OrgSetByUser behavior depends on the result
	assert.Empty(t, updatedConfig.PreferredOrg(), "PreferredOrg should remain empty when inheriting from blank global")
}

// Test that UpdateFolderConfigOrg is skipped when config is unchanged and global org hasn't changed
func Test_updateFolderConfig_SkipsUpdateWhenConfigUnchanged(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	require.NoError(t, err)

	// Setup folderConfig
	engineConfig := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath, "test-org", true)

	config.SetOrganization(engine.GetConfiguration(), "test-org")

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
	UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	// Verify config remains unchanged by reading directly from configuration
	snap := types.ReadFolderConfigSnapshot(engineConfig, folderPath)
	assert.Equal(t, "test-org", snap.PreferredOrg)
	assert.True(t, snap.OrgSetByUser, "Should remain true since UpdateFolderConfigOrg was skipped")
}

func Test_updateFolderConfig_HandlesNilStoredConfig(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)

	// Use a non-existent path that might return nil
	folderPath := types.FilePath("/non/existent/path")

	config.SetOrganization(engine.GetConfiguration(), "test-org")

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
	UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
	// If we get here without panic, the nil check worked
}

func Test_InitializeSettings(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)

	t.Run("device ID is passed", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		deviceId := "test-device-id"

		InitializeSettings(engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{DeviceId: deviceId})

		assert.Equal(t, deviceId, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingDeviceId)))
	})

	t.Run("device ID is not passed", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		deviceId := engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingDeviceId))

		InitializeSettings(engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{})

		assert.Equal(t, deviceId, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingDeviceId)))
	})

	t.Run("activateSnykCodeSecurity enables SnykCode via OR on init", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)

		InitializeSettings(engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}},
		})

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "snyk_code_enabled should enable Snyk Code on init")
	})
	t.Run("activateSnykCodeSecurity not passed does not enable SnykCode on init", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)

		InitializeSettings(engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{})

		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	})

	t.Run("custom path configuration", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)

		first := "first"
		second := "second"

		upperCasePathKey := "PATH"
		caseSensitivePathKey := "Path"
		t.Setenv(caseSensitivePathKey, "something_meaningful")

		// Path is init-only; use InitializeSettings
		InitializeSettings(engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{Path: first})
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), first+string(os.PathListSeparator)))

		InitializeSettings(engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{Path: second})
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), second+string(os.PathListSeparator)))
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), first))

		// reset path and set auth method
		InitializeSettings(engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{
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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false in auto mode")
	assert.Equal(t, setup.engine.GetConfiguration().GetString(configuration.ORGANIZATION), updatedConfig.PreferredOrg(), "PreferredOrg should inherit from global")
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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

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

	folders := config.GetWorkspace(setup.engine.GetConfiguration()).Folders()
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(folders), gomock.Any()).
		Times(1)

	types.SetAutoDeterminedOrg(setup.engine.GetConfiguration(), setup.folderPath, "auto-determined-org")

	newUserOrg := "new-user-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: newUserOrg},
			},
		},
	}
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "new-user-org", updatedConfig.PreferredOrg(), "PreferredOrg should be updated")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be true after org change")
}

func Test_updateFolderConfig_StoredUserOrg_PreservedOnUpdate(t *testing.T) {
	setup := setupFolderConfigTest(t)

	setup.createStoredConfig("user-chosen-org", true)
	config.SetOrganization(setup.engine.GetConfiguration(), "global-org-id")

	userChosenOrg := "user-chosen-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: userChosenOrg},
			},
		},
	}
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "user-chosen-org", updatedConfig.PreferredOrg(), "User-set org should be preserved")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should remain true")
}

// Test: AutoDeterminedOrg is missing and needs to be set
// When org settings change, updateFolderConfigOrg is called which sets AutoDeterminedOrg
func Test_updateFolderConfig_MissingAutoDeterminedOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup folderConfig WITHOUT AutoDeterminedOrg (simulating old config)
	engineConfig := setup.engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, setup.folderPath, "test-org", true)

	config.SetOrganization(setup.engine.GetConfiguration(), "global-org-id")

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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "user-manual-org", updatedConfig.PreferredOrg(), "PreferredOrg should be set to user choice")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be true after user sets org")
}

func Test_updateFolderConfig_Unauthenticated_UserSetsPreferredOrg(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)

	engineConfig := engine.GetConfiguration()
	folderPath := types.FilePath(t.TempDir())

	config.SetOrganization(engine.GetConfiguration(), "")

	userChosenOrg := "user-chosen-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: userChosenOrg},
			},
		},
	}
	UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	updatedConfig, err := folderconfig.GetOrCreateFolderConfig(engineConfig, folderPath, engine.GetLogger())
	require.NoError(t, err)
	updatedConfig.ConfigResolver = types.NewMinimalConfigResolver(engineConfig)
	assert.Equal(t, "user-chosen-org", updatedConfig.PreferredOrg(), "PreferredOrg should be set")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be true when user chose org")
}

func Test_updateFolderConfig_ProcessesLspFolderConfigUpdates(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup folderConfig
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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	// Verify: UserOverrides should be set in folderConfig
	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic))
	assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanNetNew))
}

// FC-105: UpdateSettings correctly processes new map format with folder configs
func Test_FC105_WriteSettings_OldFormat_ProcessesSettingsStruct(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)

	folderPath := types.FilePath(t.TempDir())
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath)

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

	UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "old format ActivateSnykCode should be applied")
	assert.Equal(t, "https://api.fc105.snyk.io", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))

	engineConfig := engine.GetConfiguration()
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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic))
	scanAutoKey := configresolver.UserFolderKey(string(types.PathKey(setup.folderPath)), types.SettingScanAutomatic)
	scanAutoVal := setup.engineConfig.Get(scanAutoKey)
	lf, ok := scanAutoVal.(*configresolver.LocalConfigField)
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
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	// Verify: UserFolderKey prefix key must be written (dual-write from SetUserOverride)
	// processSingleLspFolderConfig must set ConfigResolver before ApplyLspUpdate
	prefixKeyConfig := setup.engine.GetConfiguration()
	normalizedPath := string(types.PathKey(setup.folderPath))
	scanAutoKey := configresolver.UserFolderKey(normalizedPath, types.SettingScanAutomatic)
	require.True(t, prefixKeyConfig.IsSet(scanAutoKey),
		"UserFolderKey should be set in configuration when processSingleLspFolderConfig applies user override (fc.conf must be set before ApplyLspUpdate)")
}

func Test_validateLockedFields_UsesNewOrgPolicyOnOrgSwitch(t *testing.T) {
	t.Run("rejects locked settings from new org when PreferredOrg changes simultaneously", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		// Folder currently belongs to org-A (no locks)
		setup.createStoredConfig("org-a", true)

		// Write org-B locked config to GAF so ConfigResolver can read it via RemoteOrgKey
		prefixKeyConf := setup.engine.GetConfiguration()
		orgConfigB := types.NewLDXSyncOrgConfig("org-b")
		orgConfigB.SetField(types.SettingSnykCodeEnabled, true, true, "group") // locked
		types.WriteOrgConfigToConfiguration(prefixKeyConf, orgConfigB)

		// Set up a real ConfigResolver so validateLockedFields can use it.
		resolver := testutil.DefaultConfigResolver(setup.engine)
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

		rejected := validateLockedFields(setup.engine.GetConfiguration(), folderConfig, &incoming, setup.logger)

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

		// Write org-A locked config to GAF so ConfigResolver can read it via RemoteOrgKey
		prefixKeyConf := setup.engine.GetConfiguration()
		orgConfigA := types.NewLDXSyncOrgConfig("org-a")
		orgConfigA.SetField(types.SettingSnykCodeEnabled, true, true, "group") // locked
		types.WriteOrgConfigToConfiguration(prefixKeyConf, orgConfigA)
		// org-B has no locks

		resolver := testutil.DefaultConfigResolver(setup.engine)
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

		rejected := validateLockedFields(setup.engine.GetConfiguration(), folderConfig, &incoming, setup.logger)

		assert.False(t, rejected, "should allow changes when new org has no locks")
		assert.NotNil(t, incoming.Settings[types.SettingSnykCodeEnabled], "setting should remain since new org doesn't lock it")
	})
}

func Test_updateFolderConfig_SwitchFromManualToAutoOrg_BlanksPreferredOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Folder has a user-set org
	setup.createStoredConfig("user-chosen-org", true)

	// User sends orgSetByUser=false to switch back to automatic mode
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingOrgSetByUser: {Value: false, Changed: true},
			},
		},
	}
	UpdateSettings(setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false after switching to automatic")
	assert.Empty(t, updatedConfig.PreferredOrg(), "PreferredOrg should be blanked when switching to automatic mode")
}

func Test_validateLockedFields_RestoresConfigAfterValidation(t *testing.T) {
	setup := setupFolderConfigTest(t)
	setup.createStoredConfig("org-a", true)

	prefixKeyConf := setup.engine.GetConfiguration()

	// Write org-B locked config
	orgConfigB := types.NewLDXSyncOrgConfig("org-b")
	orgConfigB.SetField(types.SettingSnykCodeEnabled, true, true, "group")
	types.WriteOrgConfigToConfiguration(prefixKeyConf, orgConfigB)

	resolver := testutil.DefaultConfigResolver(setup.engine)
	di.SetConfigResolver(resolver)

	// Capture original config state
	folderPath := string(types.PathKey(setup.folderPath))
	orgKey := configresolver.UserFolderKey(folderPath, types.SettingOrgSetByUser)
	prefKey := configresolver.UserFolderKey(folderPath, types.SettingPreferredOrg)
	origOrgVal := prefixKeyConf.Get(orgKey)
	origPrefVal := prefixKeyConf.Get(prefKey)

	incoming := types.LspFolderConfig{
		FolderPath: setup.folderPath,
		Settings: map[string]*types.ConfigSetting{
			types.SettingPreferredOrg:    {Value: "org-b"},
			types.SettingSnykCodeEnabled: {Value: false, Changed: true},
		},
	}

	folderConfig := setup.getUpdatedConfig()
	validateLockedFields(prefixKeyConf, folderConfig, &incoming, setup.logger)

	// Config should be restored to original state after validation
	assert.Equal(t, origOrgVal, prefixKeyConf.Get(orgKey), "OrgSetByUser config key should be restored after validation")
	assert.Equal(t, origPrefVal, prefixKeyConf.Get(prefKey), "PreferredOrg config key should be restored after validation")
}

func Test_applySeverityFilter_AcceptsSeverityFilterStruct(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	sf := &types.SeverityFilter{Critical: true, High: false, Medium: true, Low: false}

	UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingEnabledSeverities: {Value: sf, Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	actual := config.GetFilterSeverity(engine.GetConfiguration())
	assert.True(t, actual.Critical)
	assert.False(t, actual.High)
	assert.True(t, actual.Medium)
	assert.False(t, actual.Low)
}

func Test_SettingIsLspInitialized_UseBareKey(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// bare key should default to false
	assert.False(t, conf.GetBool(types.SettingIsLspInitialized))

	// set with bare key
	conf.Set(types.SettingIsLspInitialized, true)

	// read with bare key should return true
	assert.True(t, conf.GetBool(types.SettingIsLspInitialized))
}

func Test_applySeverityFilter_AcceptsSeverityFilterValueStruct(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	sf := types.SeverityFilter{Critical: false, High: true, Medium: false, Low: true}

	UpdateSettings(engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingEnabledSeverities: {Value: sf, Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	actual := config.GetFilterSeverity(engine.GetConfiguration())
	assert.False(t, actual.Critical)
	assert.True(t, actual.High)
	assert.False(t, actual.Medium)
	assert.True(t, actual.Low)
}
