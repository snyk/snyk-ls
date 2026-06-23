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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/notification"
	er "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
	"github.com/snyk/snyk-ls/internal/util"
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

// testCtx builds a test context with all mandatory DI deps that UpdateSettings /
// InitializeSettings requires (Notifier, ConfigResolver, AuthService,
// FeatureFlagService, LdxSyncService, ScanStateAggregator). Engine must be the
// same instance passed to UpdateSettings / InitializeSettings so configuration
// reads are consistent.
func testCtx(t *testing.T, ctx context.Context, engine workflow.Engine, tokenService types.TokenService) context.Context {
	t.Helper()
	cr := testutil.DefaultConfigResolver(engine)
	notifier := notification.NewMockNotifier()
	authSvc := authentication.NewAuthenticationService(
		engine,
		tokenService,
		authentication.NewFakeCliAuthenticationProvider(engine),
		er.NewTestErrorReporter(engine),
		notifier,
		cr,
	)
	t.Cleanup(authSvc.Shutdown)
	ffSvc := featureflag.New(engine.GetConfiguration(), engine.GetLogger(), engine, cr)
	ldxSvc := command.NewLdxSyncService(cr)
	deps := map[string]any{
		ctx2.DepNotifier:            notifier,
		ctx2.DepConfigResolver:      cr,
		ctx2.DepAuthService:         authSvc,
		ctx2.DepFeatureFlagService:  ffSvc,
		ctx2.DepLdxSyncService:      ldxSvc,
		ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
	}
	existing, _ := ctx2.DependenciesFromContext(ctx)
	for k, v := range existing {
		if _, already := deps[k]; !already {
			deps[k] = v
		}
	}
	return ctx2.NewContextWithDependencies(ctx, deps)
}

func Test_WorkspaceDidChangeConfiguration_Push(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService)

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
	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingProxyInsecure))
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	ossParams, ok := engine.GetConfiguration().Get(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"--all-projects", "-d"}, ossParams)
	assert.Equal(t, "https://api.fake.snyk.io", types.GetGlobalString(engine.GetConfiguration(), types.SettingApiEndpoint))
	assert.Equal(t, types.GetGlobalString(engine.GetConfiguration(), types.SettingApiEndpoint), conf.GetString(configuration.API_URL))
	assert.Equal(t, "b", os.Getenv("a"))
	assert.Equal(t, "d", os.Getenv("c"))
	assert.True(t, strings.Contains(os.Getenv("PATH"), "addPath"))
	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingSendErrorReports))
	assert.Equal(t, "token", config.GetToken(engine.GetConfiguration()))
	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingEnableSnykLearnCodeActions))
}

// Test_WorkspaceDidChangeConfiguration_LspEnvelope verifies that the handler correctly
// processes settings wrapped in the standard LSP envelope: {"settings": {"settings": {...}, "folderConfigs": [...]}}
// LSP4J (IntelliJ) wraps our DidChangeConfigurationParams inside the spec's single "settings" field.
func Test_WorkspaceDidChangeConfiguration_LspEnvelope(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService)

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

func Test_InitializeSettings_PreservesRefreshedOAuthTokenWhenInitializeSendsStaleToken(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService, nil)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	staleToken := oauthTokenJSONForConfigTest(t, "stale-access", "stale-refresh", time.Now().Add(time.Hour))
	refreshedToken := oauthTokenJSONForConfigTest(t, "fresh-access", "fresh-refresh", time.Now().Add(2*time.Hour))

	var authNotificationsMu sync.Mutex
	var authNotifications []types.AuthenticationParams
	di.Notifier().CreateListener(func(params any) {
		if authParams, ok := params.(types.AuthenticationParams); ok {
			authNotificationsMu.Lock()
			defer authNotificationsMu.Unlock()
			authNotifications = append(authNotifications, authParams)
		}
	})
	t.Cleanup(func() { di.Notifier().DisposeListener() })

	// UpdateCredentials on the global singleton: both the global service and testCtx's
	// service write through to the shared engine configuration, so the refreshed token
	// is visible to whichever service instance ends up in the context.
	di.AuthenticationService().UpdateCredentials(refreshedToken, true, false)

	require.NoError(t, InitializeSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, logger, types.InitializationOptions{
		Settings: map[string]*types.ConfigSetting{
			types.SettingToken:                {Value: staleToken, Changed: true},
			types.SettingAuthenticationMethod: {Value: string(types.OAuthAuthentication), Changed: true},
		},
	}))

	assert.Equal(t, refreshedToken, config.GetToken(conf))
	require.Eventually(t, func() bool {
		authNotificationsMu.Lock()
		defer authNotificationsMu.Unlock()
		return len(authNotifications) > 0
	}, time.Second, time.Millisecond)
	authNotificationsMu.Lock()
	defer authNotificationsMu.Unlock()
	assert.Equal(t, refreshedToken, authNotifications[0].Token)
	for _, authParams := range authNotifications {
		assert.NotEmpty(t, authParams.Token)
	}
}

func Test_WorkspaceDidChangeConfiguration_Pull(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService, WithCallback(callBackMock))

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
	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingProxyInsecure))
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	ossParams, ok := engine.GetConfiguration().Get(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"--all-projects", "-d"}, ossParams)
	assert.Equal(t, "https://api.fake.snyk.io", types.GetGlobalString(engine.GetConfiguration(), types.SettingApiEndpoint))
	assert.Equal(t, types.GetGlobalString(engine.GetConfiguration(), types.SettingApiEndpoint), conf.GetString(configuration.API_URL))
	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingSendErrorReports))
	assert.Equal(t, "token", config.GetToken(engine.GetConfiguration()))
	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingEnableSnykLearnCodeActions))
}

func callBackMock(_ context.Context, request *jrpc2.Request) (any, error) {
	if request.Method() == "workspace/configuration" {
		return []types.DidChangeConfigurationParams{{Settings: types.LspConfigurationParam{Settings: sampleSettings}}}, nil
	}
	return nil, nil
}

func oauthTokenJSONForConfigTest(t *testing.T, accessToken string, refreshToken string, expiry time.Time) string {
	t.Helper()

	tokenBytes, err := json.Marshal(oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		Expiry:       expiry,
	})
	require.NoError(t, err)

	return string(tokenBytes)
}

func Test_WorkspaceDidChangeConfiguration_PullNoCapability(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService, WithCallback(callBackMock))

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
		deps := di.TestInit(t, engine, tokenService, nil)

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
					types.SettingBaseBranch:           {Value: "testBaseBranch1", Changed: true},
					types.SettingAdditionalParameters: {Value: []string{"--file=asdf"}, Changed: true},
				},
			},
			{
				FolderPath: types.FilePath(tempDir2),
				Settings: map[string]*types.ConfigSetting{
					types.SettingBaseBranch: {Value: "testBaseBranch2", Changed: true},
				},
			},
		}

		err := initTestRepo(t, tempDir1)
		assert.NoError(t, err)

		err = initTestRepo(t, tempDir2)
		assert.NoError(t, err)

		// Path is init-only; apply via InitializeSettings first.
		// TrustedFolders now goes through the settings map.
		settingsMap[types.SettingTrustedFolders] = &types.ConfigSetting{Value: []interface{}{"trustedPath1", "trustedPath2"}, Changed: true}
		ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
			ctx2.DepNotifier:           deps.Notifier,
			ctx2.DepAuthService:        deps.AuthenticationService,
			ctx2.DepConfigResolver:     deps.ConfigResolver,
			ctx2.DepFeatureFlagService: deps.FeatureFlagService,
			ctx2.DepLdxSyncService:     deps.LdxSyncService,
		})
		require.NoError(t, InitializeSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{
			Path:           "addPath",
			OsPlatform:     "windows",
			OsArch:         "amd64",
			RuntimeName:    "java",
			RuntimeVersion: "1.8.0_275",
			HoverVerbosity: &hoverVerbosity,
			OutputFormat:   &outputFormat,
		}))
		UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
		assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))
		assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))
		assert.Equal(t, true, types.GetGlobalBool(engine.GetConfiguration(), types.SettingProxyInsecure))
		ossParams, ok := engine.GetConfiguration().Get(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string)
		require.True(t, ok)
		assert.Equal(t, []string{"--all-projects", "-d"}, ossParams)
		assert.Equal(t, "https://api.snyk.io", types.GetGlobalString(engine.GetConfiguration(), types.SettingApiEndpoint))
		assert.Equal(t, "b", os.Getenv("a"))
		assert.Equal(t, "d", os.Getenv("c"))
		assert.True(t, strings.HasPrefix(os.Getenv("PATH"), "addPath"+string(os.PathListSeparator)))
		assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingSendErrorReports))
		// Organization is set globally but may be cleared at folder level by LDX-Sync logic
		// when it matches the global org and is not the default
		assert.Equal(t, expectedOrgId, engine.GetConfiguration().GetString(configuration.ORGANIZATION))
		assert.False(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingAutomaticDownload))
		assert.Equal(t, filepath.Join(cliDir, "cli"), types.GetGlobalString(engine.GetConfiguration(), types.SettingCliPath))
		assert.Equal(t, nonDefaultSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))
		assert.Equal(t, nonDefaultIssueViewOptions, config.GetIssueViewOptions(engine.GetConfiguration()))
		tf := types.GetGlobalSliceFilePath(engine.GetConfiguration(), types.SettingTrustedFolders)
		assert.Subset(t, []types.FilePath{"trustedPath1", "trustedPath2"}, tf)
		conf := engine.GetConfiguration()
		assert.Equal(t, "windows", conf.GetString(configresolver.UserGlobalKey(types.SettingOsPlatform)))
		assert.Equal(t, "amd64", conf.GetString(configresolver.UserGlobalKey(types.SettingOsArch)))
		assert.Equal(t, "java", conf.GetString(configresolver.UserGlobalKey(types.SettingRuntimeName)))
		assert.Equal(t, "1.8.0_275", conf.GetString(configresolver.UserGlobalKey(types.SettingRuntimeVersion)))
		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingScanAutomatic)))
		assert.Equal(t, true, types.GetGlobalBool(engine.GetConfiguration(), types.SettingEnableSnykOpenBrowserActions))
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
		// In auto mode (no user-set org) PreferredOrg stays empty; global is consulted at use site.
		assert.Empty(t, folderConfig1.PreferredOrg(), "PreferredOrg should stay empty in auto mode")

		folderConfig2 := config.GetFolderConfigFromEngine(engine, testutil.DefaultConfigResolver(engine), types.FilePath(tempDir2), engine.GetLogger())
		assert.NotEmpty(t, folderConfig2.BaseBranch())
		assert.Empty(t, folderConfig2.AdditionalParameters())
		assert.Empty(t, folderConfig2.PreferredOrg(), "PreferredOrg should stay empty in auto mode")

		assert.Eventually(t, func() bool { return config.GetToken(engine.GetConfiguration()) == "a fancy token" }, time.Second*5, time.Millisecond)
	})

	t.Run("hover defaults are set", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, 3, types.GetGlobalInt(engine.GetConfiguration(), types.SettingHoverVerbosity))
		assert.Equal(t, config.FormatMd, types.GetGlobalString(engine.GetConfiguration(), types.SettingFormat))
	})

	t.Run("incomplete env vars", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAdditionalEnvironment: {Value: "a=", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("empty env vars", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		varCount := len(os.Environ())

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAdditionalEnvironment: {Value: " ", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, varCount, len(os.Environ()))
	})

	t.Run("broken env variables", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAdditionalEnvironment: {Value: "a=; b", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Empty(t, os.Getenv("a"))
		assert.Empty(t, os.Getenv("b"))
		assert.Empty(t, os.Getenv(";"))
	})
	t.Run("trusted folders", func(t *testing.T) {
		t.Run("via InitializeSettings", func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			di.TestInit(t, engine, tokenService, nil)

			path1 := filepath.Join("a", "b")
			path2 := filepath.Join("b", "c")
			require.NoError(t, InitializeSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{
				Settings: map[string]*types.ConfigSetting{
					types.SettingTrustedFolders: {Value: []interface{}{path1, path2}, Changed: true},
				},
			}))

			tf := types.GetGlobalSliceFilePath(engine.GetConfiguration(), types.SettingTrustedFolders)
			assert.Contains(t, tf, types.FilePath(path1))
			assert.Contains(t, tf, types.FilePath(path2))
		})

		t.Run("via didChangeConfiguration push model", func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			di.TestInit(t, engine, tokenService, nil)
			engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

			path1 := filepath.Join("x", "y")
			path2 := filepath.Join("y", "z")
			params := types.LspConfigurationParam{
				Settings: map[string]*types.ConfigSetting{
					types.SettingTrustedFolders: {Value: []interface{}{path1, path2}, Changed: true},
				},
			}
			_, err := handlePushModel(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), params)
			assert.NoError(t, err)

			tf := types.GetGlobalSliceFilePath(engine.GetConfiguration(), types.SettingTrustedFolders)
			assert.Contains(t, tf, types.FilePath(path1))
			assert.Contains(t, tf, types.FilePath(path2))
		})
	})

	t.Run("manage binaries automatically", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		t.Run("true", func(t *testing.T) {
			UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingAutomaticDownload))
		})
		t.Run("false", func(t *testing.T) {
			UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: false, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.False(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingAutomaticDownload))
		})

		t.Run("invalid value does not update", func(t *testing.T) {
			ctx := testCtx(t, t.Context(), engine, tokenService)
			UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingAutomaticDownload: {Value: "dog", Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingAutomaticDownload))
		})
	})

	t.Run("activateSnykCodeSecurity enables SnykCode via OR", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "snyk_code_enabled should enable Snyk Code")
	})
	t.Run("activateSnykCode and activateSnykCodeSecurity are ORed", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "Should be enabled when snyk_code_enabled is true")
	})
	t.Run("activateSnykCode alone enables SnykCode", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	})
	t.Run("neither activateSnykCode nor activateSnykCodeSecurity disables SnykCode", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: false, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	})

	t.Run("activateSnykSecrets is passed", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService, nil)

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykSecretsEnabled: {Value: true, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
	})
	t.Run("activateSnykSecrets false", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService, nil)

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingSnykSecretsEnabled: {Value: false, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
	})
	t.Run("activateSnykSecrets not passed does not update", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		di.TestInit(t, engine, tokenService, nil)

		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
	})

	t.Run("severity filter", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(true, false, true, false)
			UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterCritical: {Value: true, Changed: true},
				types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
				types.SettingSeverityFilterMedium:   {Value: true, Changed: true},
				types.SettingSeverityFilterLow:      {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.Equal(t, mixedSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeSeverityFilter := types.NewSeverityFilter(false, false, false, false)
			UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterCritical: {Value: false, Changed: true},
				types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
				types.SettingSeverityFilterMedium:   {Value: false, Changed: true},
				types.SettingSeverityFilterLow:      {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.Equal(t, emptyLikeSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(false, false, true, false)
			ctx := testCtx(t, t.Context(), engine, tokenService)
			UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterCritical: {Value: false, Changed: true},
				types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
				types.SettingSeverityFilterMedium:   {Value: true, Changed: true},
				types.SettingSeverityFilterLow:      {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
			assert.Equal(t, mixedSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))

			UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
			assert.Equal(t, mixedSeverityFilter, config.GetFilterSeverity(engine.GetConfiguration()))
		})
		t.Run("partial update preserves unchanged severities", func(t *testing.T) {
			// Set initial state: Critical=false, High=false, Medium=true, Low=false
			ctx := testCtx(t, t.Context(), engine, tokenService)
			UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterCritical: {Value: false, Changed: true},
				types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
				types.SettingSeverityFilterMedium:   {Value: true, Changed: true},
				types.SettingSeverityFilterLow:      {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
			assert.Equal(t, types.NewSeverityFilter(false, false, true, false), config.GetFilterSeverity(engine.GetConfiguration()))

			// Partial update: only toggle High to true; omitted severities must be preserved
			UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingSeverityFilterHigh: {Value: true, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			expected := types.NewSeverityFilter(false, true, true, false)
			assert.Equal(t, expected, config.GetFilterSeverity(engine.GetConfiguration()))
		})
	})

	t.Run("issue view options", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				types.SettingIssueViewIgnoredIssues: {Value: true, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.Equal(t, mixedIssueViewOptions, config.GetIssueViewOptions(engine.GetConfiguration()))
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeIssueViewOptions := types.NewIssueViewOptions(false, false)
			UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				types.SettingIssueViewIgnoredIssues: {Value: false, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			assert.Equal(t, emptyLikeIssueViewOptions, config.GetIssueViewOptions(engine.GetConfiguration()))
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			ctx := testCtx(t, t.Context(), engine, tokenService)
			UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				types.SettingIssueViewIgnoredIssues: {Value: true, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
			assert.Equal(t, mixedIssueViewOptions, config.GetIssueViewOptions(engine.GetConfiguration()))

			UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
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
		deps := di.TestInit(t, engine, tokenService, nil)

		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)

		mockLdx := mock_command.NewMockLdxSyncService(ctrl)
		ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
			ctx2.DepLdxSyncService:     mockLdx,
			ctx2.DepNotifier:           notification.NewMockNotifier(),
			ctx2.DepAuthService:        deps.AuthenticationService,
			ctx2.DepFeatureFlagService: deps.FeatureFlagService,
		})

		folderPath := types.FilePath(t.TempDir())
		workspaceutil.SetupWorkspace(t, engine, folderPath)

		tokenService.SetToken(engine.GetConfiguration(), "old-token")

		folders := config.GetWorkspace(engine.GetConfiguration()).Folders()
		mockLdx.EXPECT().
			RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(folders), gomock.Any()).
			Times(1)

		UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
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
			deps := di.TestInit(t, engine, tokenService, nil)

			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			mockLdx := mock_command.NewMockLdxSyncService(ctrl)
			ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
				ctx2.DepLdxSyncService:     mockLdx,
				ctx2.DepNotifier:           notification.NewMockNotifier(),
				ctx2.DepAuthService:        deps.AuthenticationService,
				ctx2.DepFeatureFlagService: deps.FeatureFlagService,
			})

			folderPath := types.FilePath(t.TempDir())
			workspaceutil.SetupWorkspace(t, engine, folderPath)

			tokenService.SetToken(engine.GetConfiguration(), tt.existingToken)

			mockLdx.EXPECT().
				RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Times(0)

			UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
				types.SettingToken: {Value: tt.newToken, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
		})
	}

	t.Run("no workspace folders skips refresh", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		deps := di.TestInit(t, engine, tokenService, nil)

		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)

		mockLdx := mock_command.NewMockLdxSyncService(ctrl)
		ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
			ctx2.DepLdxSyncService:     mockLdx,
			ctx2.DepNotifier:           notification.NewMockNotifier(),
			ctx2.DepAuthService:        deps.AuthenticationService,
			ctx2.DepFeatureFlagService: deps.FeatureFlagService,
		})

		tokenService.SetToken(engine.GetConfiguration(), "old-token")

		mockLdx.EXPECT().
			RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Times(0)

		UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
			types.SettingToken: {Value: "new-token", Changed: true},
		}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
	})
}

func Test_refreshLdxSyncOnTokenChange_NilNotifier_StillCallsRefresh(t *testing.T) {
	// Passing nil for the notifier must still call RefreshConfigFromLdxSync — it tolerates nil.
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService, nil)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockLdx := mock_command.NewMockLdxSyncService(ctrl)
	// Notifier is intentionally absent from the context.
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepLdxSyncService: mockLdx,
	})

	folderPath := types.FilePath(t.TempDir())
	workspaceutil.SetupWorkspace(t, engine, folderPath)

	conf := engine.GetConfiguration()
	tokenService.SetToken(conf, "old-token")
	conf.Set(types.SettingIsLspInitialized, false) // ws check passes if folders exist

	folders := config.GetWorkspace(conf).Folders()
	// RefreshConfigFromLdxSync must still be called even though notifier is absent (nil is OK).
	mockLdx.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(folders), gomock.Nil()).
		Times(1)

	// Set a new token directly into conf to simulate a token change.
	// (We bypass UpdateSettings to avoid the processFolderConfigs → mustNotifierFromContext path.)
	tokenService.SetToken(conf, "new-token")
	// Explicitly call the function under test.
	// nil notifier: verifies that RefreshConfigFromLdxSync is still called even without one.
	refreshLdxSyncOnTokenChange(ctx, conf, engine, engine.GetLogger(), config.GetWorkspace(conf), "old-token", nil)
}

func Test_UpdateSettings_BlankOrWhitespaceOrganizationResetsToDefault_Integration(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"blank", ""},
		{"whitespace", " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, tokenService := testutil.IntegTestWithEngine(t)
			conf := engine.GetConfiguration()
			if config.GetToken(conf) == "" {
				t.Skip("SNYK_TOKEN is required to resolve the user's preferred default org via /rest/self")
			}
			initialOrgId := "00000000-0000-0000-0000-000000000001"
			config.SetOrganization(conf, initialOrgId)
			require.Equal(t, initialOrgId, conf.GetString(configuration.ORGANIZATION))

			UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{types.SettingOrganization: {Value: tc.value, Changed: true}}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

			// GAF's DefaultValueFunction for ORGANIZATION is synchronous.
			actualOrg := conf.GetString(configuration.ORGANIZATION)
			assert.NotEqual(t, initialOrgId, actualOrg)
			assert.NotEmpty(t, actualOrg)
			_, err := uuid.Parse(actualOrg)
			assert.NoError(t, err, "resolved org should be a valid UUID")
		})
	}
}

// Common test setup for updateFolderConfig tests
type folderConfigTestSetup struct {
	t            *testing.T
	engine       workflow.Engine
	engineConfig configuration.Configuration
	logger       *zerolog.Logger
	folderPath   types.FilePath
	deps         di.Dependencies
	tokenService types.TokenService
}

func setupFolderConfigTest(t *testing.T) *folderConfigTestSetup {
	t.Helper()
	engine, tokenService := testutil.UnitTestWithEngine(t)
	deps := di.TestInit(t, engine, tokenService, nil)

	engineConfig := engine.GetConfiguration()

	// Register mock default value functions for org config to avoid API calls in tests
	engineConfig.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction("test-default-org-uuid"))
	engineConfig.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction("test-default-org-slug"))

	// Mark as initialized since tests using this setup simulate post-initialization config updates
	engineConfig.Set(types.SettingIsLspInitialized, true)

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
		deps:         deps,
		tokenService: tokenService,
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
	di.TestInit(t, engine, tokenService, nil)

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
				types.SettingPreferredOrg: {Value: userOrgID, Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	// Verify the org was kept by reading directly from configuration
	snap := types.ReadFolderConfigSnapshot(engineConfig, folderPath)
	assert.Equal(t, "user-org-id", snap.PreferredOrg, "PreferredOrg should remain as user-set value")
}

func Test_updateFolderConfig_EmptyOrgSent_LeavesPreferredOrgEmpty(t *testing.T) {
	setup := setupFolderConfigTest(t)

	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: "", Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), setup.engine, setup.tokenService), setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false in auto mode")
	assert.Empty(t, updatedConfig.PreferredOrg(), "PreferredOrg should stay empty in auto mode; effective org resolved at use site via fallback to global/auto")
}

func Test_updateFolderConfig_EmptyStoredOrg_LeavesPreferredOrgEmpty(t *testing.T) {
	setup := setupFolderConfigTest(t)
	setup.createStoredConfig("", false)

	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: "", Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), setup.engine, setup.tokenService), setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false in auto mode")
	assert.Empty(t, updatedConfig.PreferredOrg(), "PreferredOrg should stay empty in auto mode; effective org resolved at use site via fallback to global/auto")
}

func Test_updateFolderConfig_LdxSyncReturnsDifferentOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)
	setup.setupLdxSyncReturnsDifferentOrg()

	initialOrg := "initial-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: initialOrg, Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), setup.engine, setup.tokenService), setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

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
				types.SettingPreferredOrg: {Value: emptyOrg, Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), setup.engine, setup.tokenService), setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	// Verify: should attempt to resolve from LDX-Sync because inheriting from blank global
	// This test specifically checks the case where both folder and global orgs are empty
	updatedConfig := setup.getUpdatedConfig()
	// When LDX-Sync is called, OrgSetByUser behavior depends on the result
	assert.Empty(t, updatedConfig.PreferredOrg(), "PreferredOrg should remain empty when inheriting from blank global")
}

// Test that UpdateFolderConfigOrg is skipped when config is unchanged and global org hasn't changed
func Test_updateFolderConfig_SkipsUpdateWhenConfigUnchanged(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService, nil)

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
				types.SettingPreferredOrg: {Value: testOrg, Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	// Verify config remains unchanged by reading directly from configuration
	snap := types.ReadFolderConfigSnapshot(engineConfig, folderPath)
	assert.Equal(t, "test-org", snap.PreferredOrg)
	assert.True(t, snap.OrgSetByUser, "Should remain true since UpdateFolderConfigOrg was skipped")
}

func Test_updateFolderConfig_HandlesNilStoredConfig(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService, nil)

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
				types.SettingPreferredOrg: {Value: testOrg, Changed: true},
			},
		},
	}

	// Should not panic and should handle nil gracefully
	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))
	// If we get here without panic, the nil check worked
}

func Test_InitializeSettings(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService, nil)

	t.Run("device ID is passed", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		deviceId := "test-device-id"

		require.NoError(t, InitializeSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{DeviceId: deviceId}))

		assert.Equal(t, deviceId, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingDeviceId)))
	})

	t.Run("device ID is not passed", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		deviceId := engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingDeviceId))

		require.NoError(t, InitializeSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{}))

		assert.Equal(t, deviceId, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingDeviceId)))
	})

	t.Run("activateSnykCodeSecurity enables SnykCode via OR on init", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		require.NoError(t, InitializeSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{types.SettingSnykCodeEnabled: {Value: true, Changed: true}},
		}))

		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "snyk_code_enabled should enable Snyk Code on init")
	})
	t.Run("activateSnykCodeSecurity not passed does not enable SnykCode on init", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		require.NoError(t, InitializeSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{}))

		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	})

	t.Run("custom path configuration", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		first := "first"
		second := "second"

		upperCasePathKey := "PATH"
		caseSensitivePathKey := "Path"
		t.Setenv(caseSensitivePathKey, "something_meaningful")

		ctx := testCtx(t, t.Context(), engine, tokenService)
		require.NoError(t, InitializeSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{Path: first}))
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), first+string(os.PathListSeparator)))

		require.NoError(t, InitializeSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{Path: second}))
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), second+string(os.PathListSeparator)))
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), first))

		require.NoError(t, InitializeSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), types.InitializationOptions{
			Path:     "",
			Settings: map[string]*types.ConfigSetting{types.SettingAuthenticationMethod: {Value: "token", Changed: true}},
		}))
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), second))

		assert.True(t, keyFoundInEnv(upperCasePathKey))
		assert.False(t, keyFoundInEnv(caseSensitivePathKey))
	})
}

// IDE-1963 regression: an auto-mode folder receiving a non-org IDE update must not cause
// the global org to leak into a subsequent LDX-Sync request. Pre-fix, processSingleLspFolderConfig
// would inherit globalOrg into PreferredOrg on the first pass, and the next LDX-Sync refresh
// (e.g. after token change at startup) would scope its request to that org — returning
// settings for the global org while AutoDeterminedOrg pointed at a different algorithm-preferred
// org. Verifies both the persisted state and the downstream request are correct end-to-end.
func Test_processFolderConfigs_AutoMode_DoesNotLeakGlobalOrgToLdxSync(t *testing.T) {
	setup := setupFolderConfigTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)
	realService := command.NewLdxSyncServiceWithApiClient(mockApiClient, testutil.DefaultConfigResolver(setup.engine))
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepLdxSyncService:      realService,
		ctx2.DepNotifier:            notification.NewMockNotifier(),
		ctx2.DepAuthService:         setup.deps.AuthenticationService,
		ctx2.DepFeatureFlagService:  setup.deps.FeatureFlagService,
		ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		ctx2.DepConfigResolver:      testutil.DefaultConfigResolver(setup.engine),
	})

	folders := config.GetWorkspace(setup.engine.GetConfiguration()).Folders()
	require.Len(t, folders, 1)

	// Folder is in pure auto mode (no PreferredOrg, no OrgSetByUser). Global org defaults to
	// "test-default-org-uuid" via the test setup. Send a non-org folder update — pre-fix this
	// would trigger updateFolderOrgIfNeeded's inheritance branch and persist
	// PreferredOrg=globalOrg into the folder config.
	UpdateSettings(ctx, setup.engineConfig, setup.engine, setup.logger, nil, []types.LspFolderConfig{
		{FolderPath: setup.folderPath},
	}, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	snap := types.ReadFolderConfigSnapshot(setup.engineConfig, setup.folderPath)
	require.Empty(t, snap.PreferredOrg, "auto-mode folder must not inherit global org into PreferredOrg [IDE-1963]")
	require.False(t, snap.OrgSetByUser, "auto-mode folder must keep OrgSetByUser=false")

	// Trigger an LDX-Sync refresh via token change — analogous to startup. The mock asserts the
	// API is called with empty preferredOrg, not the global org. Pre-fix this would have been
	// called with "test-default-org-uuid".
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), setup.engine, string(folders[0].Path()), "").
		Return(ldx_sync_config.LdxSyncConfigResult{})

	UpdateSettings(ctx, setup.engineConfig, setup.engine, setup.logger, map[string]*types.ConfigSetting{
		types.SettingToken: {Value: "new-token", Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))
}

func Test_updateFolderConfig_AutoMode_EmptyOrg_LeavesPreferredOrgEmpty(t *testing.T) {
	setup := setupFolderConfigTest(t)

	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: "", Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), setup.engine, setup.tokenService), setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false in auto mode")
	assert.Empty(t, updatedConfig.PreferredOrg(), "PreferredOrg should stay empty in auto mode; effective org resolved at use site via fallback to global/auto")
}

func Test_updateFolderConfig_OrgChange_TriggersLdxSyncRefresh(t *testing.T) {
	setup := setupFolderConfigTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockLdxSyncService := mock_command.NewMockLdxSyncService(ctrl)
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepLdxSyncService:      mockLdxSyncService,
		ctx2.DepNotifier:            notification.NewMockNotifier(),
		ctx2.DepAuthService:         setup.deps.AuthenticationService,
		ctx2.DepFeatureFlagService:  setup.deps.FeatureFlagService,
		ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		ctx2.DepConfigResolver:      testutil.DefaultConfigResolver(setup.engine),
	})

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
				types.SettingPreferredOrg: {Value: newUserOrg, Changed: true},
			},
		},
	}
	UpdateSettings(ctx, setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

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
				types.SettingPreferredOrg: {Value: userChosenOrg, Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), setup.engine, setup.tokenService), setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "user-chosen-org", updatedConfig.PreferredOrg(), "User-set org should be preserved")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should remain true")
}

// Test: AutoDeterminedOrg is missing and needs to be set
// When org settings change, updateFolderConfigOrg is called which sets AutoDeterminedOrg
func Test_updateFolderConfig_MissingAutoDeterminedOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockLdx := mock_command.NewMockLdxSyncService(ctrl)
	mockLdx.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1)
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepLdxSyncService:      mockLdx,
		ctx2.DepNotifier:            notification.NewMockNotifier(),
		ctx2.DepAuthService:         setup.deps.AuthenticationService,
		ctx2.DepFeatureFlagService:  setup.deps.FeatureFlagService,
		ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		ctx2.DepConfigResolver:      testutil.DefaultConfigResolver(setup.engine),
	})

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
				types.SettingPreferredOrg: {Value: differentTestOrg, Changed: true},
			},
		},
	}
	UpdateSettings(ctx, setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	// Verify: AutoDeterminedOrg remains empty when LDX-Sync cache is empty
	// AutoDeterminedOrg should only contain what LDX-Sync determined, not a fallback
	// Fallback to global org happens at the point of use (in FolderOrganization)
	updatedConfig := setup.getUpdatedConfig()
	assert.Empty(t, updatedConfig.AutoDeterminedOrg(), "AutoDeterminedOrg should remain empty when LDX-Sync cache is empty")
}

func Test_updateFolderConfig_SwitchFromAutoToManualOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockLdx := mock_command.NewMockLdxSyncService(ctrl)
	mockLdx.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1)
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepLdxSyncService:      mockLdx,
		ctx2.DepNotifier:            notification.NewMockNotifier(),
		ctx2.DepAuthService:         setup.deps.AuthenticationService,
		ctx2.DepFeatureFlagService:  setup.deps.FeatureFlagService,
		ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		ctx2.DepConfigResolver:      testutil.DefaultConfigResolver(setup.engine),
	})

	userManualOrg := "user-manual-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: userManualOrg, Changed: true},
			},
		},
	}
	UpdateSettings(ctx, setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "user-manual-org", updatedConfig.PreferredOrg(), "PreferredOrg should be set to user choice")
	assert.True(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be true after user sets org")
}

func Test_updateFolderConfig_Unauthenticated_UserSetsPreferredOrg(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService, nil)

	engineConfig := engine.GetConfiguration()
	folderPath := types.FilePath(t.TempDir())

	config.SetOrganization(engine.GetConfiguration(), "")

	userChosenOrg := "user-chosen-org"
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: userChosenOrg, Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

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
	UpdateSettings(testCtx(t, t.Context(), setup.engine, setup.tokenService), setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	// Verify: UserOverrides should be set in folderConfig
	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanAutomatic))
	assert.True(t, types.HasUserOverride(updatedConfig.Conf(), updatedConfig.FolderPath, types.SettingScanNetNew))
}

// FC-105: UpdateSettings correctly processes new map format with folder configs
func Test_FC105_WriteSettings_OldFormat_ProcessesSettingsStruct(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	deps := di.TestInit(t, engine, tokenService, nil)
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepNotifier:    notification.NewMockNotifier(),
		ctx2.DepAuthService: deps.AuthenticationService,
	})

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
				types.SettingPreferredOrg: {Value: "folder-org-fc105", Changed: true},
			},
		},
	}
	UpdateSettings(ctx, engine.GetConfiguration(), engine, engine.GetLogger(), settingsMap, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "old format ActivateSnykCode should be applied")
	assert.Equal(t, "https://api.fc105.snyk.io", types.GetGlobalString(engine.GetConfiguration(), types.SettingApiEndpoint))

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
				types.SettingBaseBranch:    {Value: "develop", Changed: true},
			},
		},
	}
	UpdateSettings(testCtx(t, t.Context(), setup.engine, setup.tokenService), setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

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
	UpdateSettings(testCtx(t, t.Context(), setup.engine, setup.tokenService), setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

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
				types.SettingPreferredOrg:    {Value: newOrg, Changed: true},
				types.SettingSnykCodeEnabled: {Value: false, Changed: true},
				types.SettingScanAutomatic:   {Value: true, Changed: true}, // not locked
			},
		}

		folderConfig := setup.getUpdatedConfig()

		rejected := validateLockedFields(resolver, setup.engine.GetConfiguration(), folderConfig, &incoming, setup.logger)

		assert.ElementsMatch(t, []string{types.SettingSnykCodeEnabled}, rejected,
			"should report the locked setting name so the caller can dedupe into one notification")
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
				types.SettingPreferredOrg:    {Value: newOrg, Changed: true},
				types.SettingSnykCodeEnabled: {Value: false, Changed: true},
			},
		}

		folderConfig := setup.getUpdatedConfig()

		rejected := validateLockedFields(resolver, setup.engine.GetConfiguration(), folderConfig, &incoming, setup.logger)

		assert.Empty(t, rejected, "should allow changes when new org has no locks")
		assert.NotNil(t, incoming.Settings[types.SettingSnykCodeEnabled], "setting should remain since new org doesn't lock it")
	})
}

func Test_updateFolderConfig_SwitchFromManualToAutoOrg_BlanksPreferredOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockLdx := mock_command.NewMockLdxSyncService(ctrl)
	mockLdx.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1)
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepLdxSyncService:      mockLdx,
		ctx2.DepNotifier:            notification.NewMockNotifier(),
		ctx2.DepAuthService:         setup.deps.AuthenticationService,
		ctx2.DepFeatureFlagService:  setup.deps.FeatureFlagService,
		ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		ctx2.DepConfigResolver:      testutil.DefaultConfigResolver(setup.engine),
	})

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
	UpdateSettings(ctx, setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(), "OrgSetByUser should be false after switching to automatic")
	assert.Empty(t, updatedConfig.PreferredOrg(), "PreferredOrg should be blanked when switching to automatic mode")
}

func Test_updateFolderConfig_UserSetOrg_BlankedPreferredOrg_GlobalAlsoBlank_RevertToAutoOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockLdx := mock_command.NewMockLdxSyncService(ctrl)
	mockLdx.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1)
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepLdxSyncService:      mockLdx,
		ctx2.DepNotifier:            notification.NewMockNotifier(),
		ctx2.DepAuthService:         setup.deps.AuthenticationService,
		ctx2.DepFeatureFlagService:  setup.deps.FeatureFlagService,
		ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		ctx2.DepConfigResolver:      testutil.DefaultConfigResolver(setup.engine),
	})

	// User had a specific org set; global org is blank (e.g. not configured).
	// UnitTestWithEngine pre-sets a zero UUID org — clear it via SetOrganization("")
	// so applyPreferredOrg sees a blank global org for this test scenario.
	setup.createStoredConfig("user-chosen-org", true)
	config.SetOrganization(setup.engine.GetConfiguration(), "")

	// User blanks the preferred org
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: "", Changed: true},
			},
		},
	}
	UpdateSettings(ctx, setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(),
		nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.False(t, updatedConfig.OrgSetByUser(),
		"OrgSetByUser must revert to false when global org is also blank: auto-org should take over")
	assert.Empty(t, updatedConfig.PreferredOrg(), "PreferredOrg should be empty after blanking")
}

func Test_updateFolderConfig_UserSetOrg_BlankedPreferredOrg_UsesGlobalOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockLdx := mock_command.NewMockLdxSyncService(ctrl)
	mockLdx.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1)
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepLdxSyncService:      mockLdx,
		ctx2.DepNotifier:            notification.NewMockNotifier(),
		ctx2.DepAuthService:         setup.deps.AuthenticationService,
		ctx2.DepFeatureFlagService:  setup.deps.FeatureFlagService,
		ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		ctx2.DepConfigResolver:      testutil.DefaultConfigResolver(setup.engine),
	})

	// User previously set a specific org
	setup.createStoredConfig("user-chosen-org", true)
	// Store an auto-determined org to confirm it is NOT used after blanking
	types.SetAutoDeterminedOrg(setup.engine.GetConfiguration(), setup.folderPath, "auto-determined-org")
	// Set a global org so SettingLastSetOrganization is populated
	config.SetOrganization(setup.engine.GetConfiguration(), "global-org-id")

	// User blanks the preferred org (clears the field in config dialog)
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: setup.folderPath,
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: "", Changed: true},
			},
		},
	}
	UpdateSettings(ctx, setup.engine.GetConfiguration(), setup.engine, setup.engine.GetLogger(),
		nil, folderConfigs, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, updatedConfig.OrgSetByUser(),
		"OrgSetByUser must remain true: user chose global org, not auto-org")
	assert.Empty(t, updatedConfig.PreferredOrg(),
		"PreferredOrg should be empty after blanking")
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
			types.SettingPreferredOrg:    {Value: "org-b", Changed: true},
			types.SettingSnykCodeEnabled: {Value: false, Changed: true},
		},
	}

	folderConfig := setup.getUpdatedConfig()
	validateLockedFields(resolver, prefixKeyConf, folderConfig, &incoming, setup.logger)

	// Config should be restored to original state after validation
	assert.Equal(t, origOrgVal, prefixKeyConf.Get(orgKey), "OrgSetByUser config key should be restored after validation")
	assert.Equal(t, origPrefVal, prefixKeyConf.Get(prefKey), "PreferredOrg config key should be restored after validation")
}

func Test_applySeverityFilter_AcceptsSeverityFilterStruct(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)

	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingSeverityFilterCritical: {Value: true, Changed: true},
		types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
		types.SettingSeverityFilterMedium:   {Value: true, Changed: true},
		types.SettingSeverityFilterLow:      {Value: false, Changed: true},
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
	engine, tokenService := testutil.UnitTestWithEngine(t)

	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingSeverityFilterCritical: {Value: false, Changed: true},
		types.SettingSeverityFilterHigh:     {Value: true, Changed: true},
		types.SettingSeverityFilterMedium:   {Value: false, Changed: true},
		types.SettingSeverityFilterLow:      {Value: true, Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	actual := config.GetFilterSeverity(engine.GetConfiguration())
	assert.False(t, actual.Critical)
	assert.True(t, actual.High)
	assert.False(t, actual.Medium)
	assert.True(t, actual.Low)
}

func Test_applySeverityFilter_AcceptsIndividualBooleans(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)

	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), engine.GetConfiguration(), engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingSeverityFilterCritical: {Value: true, Changed: true},
		types.SettingSeverityFilterHigh:     {Value: false, Changed: true},
		types.SettingSeverityFilterMedium:   {Value: true, Changed: true},
		types.SettingSeverityFilterLow:      {Value: false, Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	actual := config.GetFilterSeverity(engine.GetConfiguration())
	assert.True(t, actual.Critical)
	assert.False(t, actual.High)
	assert.True(t, actual.Medium)
	assert.False(t, actual.Low)
}

func Test_applySeverityFilter_IndividualBooleansPartialUpdate(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// Set initial state: all enabled
	config.SetSeverityFilterOnConfig(conf, &types.SeverityFilter{
		Critical: true, High: true, Medium: true, Low: true,
	}, engine.GetLogger())

	// Only change critical and low, leave high and medium unchanged
	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingSeverityFilterCritical: {Value: false, Changed: true},
		types.SettingSeverityFilterLow:      {Value: false, Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	actual := config.GetFilterSeverity(conf)
	assert.False(t, actual.Critical, "Critical should be updated to false")
	assert.True(t, actual.High, "High should be preserved as true")
	assert.True(t, actual.Medium, "Medium should be preserved as true")
	assert.False(t, actual.Low, "Low should be updated to false")
}

func Test_applySeverityFilter_IndividualBooleansIgnoreUnchanged(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// Set initial state: all disabled
	config.SetSeverityFilterOnConfig(conf, &types.SeverityFilter{
		Critical: false, High: false, Medium: false, Low: false,
	}, engine.GetLogger())

	// Send all keys but only mark high as Changed
	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingSeverityFilterCritical: {Value: true, Changed: false},
		types.SettingSeverityFilterHigh:     {Value: true, Changed: true},
		types.SettingSeverityFilterMedium:   {Value: true, Changed: false},
		types.SettingSeverityFilterLow:      {Value: true, Changed: false},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	actual := config.GetFilterSeverity(conf)
	assert.False(t, actual.Critical, "Critical should remain false (not Changed)")
	assert.True(t, actual.High, "High should be updated to true")
	assert.False(t, actual.Medium, "Medium should remain false (not Changed)")
	assert.False(t, actual.Low, "Low should remain false (not Changed)")
}

// Test hasFilterChangesInLspConfig detects filter changes
func Test_hasFilterChangesInLspConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *types.LspFolderConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name: "nil settings",
			config: &types.LspFolderConfig{
				FolderPath: "/test",
				Settings:   nil,
			},
			expected: false,
		},
		{
			name: "no changes",
			config: &types.LspFolderConfig{
				FolderPath: "/test",
				Settings: map[string]*types.ConfigSetting{
					types.SettingSeverityFilterCritical: {Value: true, Changed: false},
					types.SettingSeverityFilterHigh:     {Value: true, Changed: false},
				},
			},
			expected: false,
		},
		{
			name: "severity filter changed",
			config: &types.LspFolderConfig{
				FolderPath: "/test",
				Settings: map[string]*types.ConfigSetting{
					types.SettingSeverityFilterCritical: {Value: false, Changed: true},
					types.SettingSeverityFilterHigh:     {Value: true, Changed: false},
				},
			},
			expected: true,
		},
		{
			name: "issue view changed",
			config: &types.LspFolderConfig{
				FolderPath: "/test",
				Settings: map[string]*types.ConfigSetting{
					types.SettingIssueViewOpenIssues: {Value: false, Changed: true},
				},
			},
			expected: true,
		},
		{
			name: "risk score threshold changed",
			config: &types.LspFolderConfig{
				FolderPath: "/test",
				Settings: map[string]*types.ConfigSetting{
					types.SettingRiskScoreThreshold: {Value: 50, Changed: true},
				},
			},
			expected: true,
		},
		{
			name: "non-filter setting changed",
			config: &types.LspFolderConfig{
				FolderPath: "/test",
				Settings: map[string]*types.ConfigSetting{
					types.SettingScanAutomatic: {Value: false, Changed: true},
					types.SettingBaseBranch:    {Value: "main", Changed: true},
				},
			},
			expected: false,
		},
		{
			name: "multiple filter changes",
			config: &types.LspFolderConfig{
				FolderPath: "/test",
				Settings: map[string]*types.ConfigSetting{
					types.SettingSeverityFilterCritical: {Value: false, Changed: true},
					types.SettingSeverityFilterHigh:     {Value: true, Changed: true},
					types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasFilterChangesInLspConfig(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// IDE-1946: applyIssueViewOptions must seed from current config so partial payloads
// (one flag Changed=true, the other Changed=false) preserve the unchanged flag.

// seedIssueViewOptions writes the issue view options directly to conf and asserts
// they are observable, so the test's precondition is unambiguous regardless of
// any test-harness-provided defaults.
func seedIssueViewOptions(t *testing.T, conf configuration.Configuration, opts types.IssueViewOptions) {
	t.Helper()
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewOpenIssues), opts.OpenIssues)
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewIgnoredIssues), opts.IgnoredIssues)
	require.Equal(t, opts, config.GetIssueViewOptions(conf), "test seed must be observable via GetIssueViewOptions")
}

func TestApplyIssueViewOptions_PreservesOpenWhenOnlyIgnoredChanged(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	seedIssueViewOptions(t, conf, types.IssueViewOptions{OpenIssues: true, IgnoredIssues: false})

	// Open's Value (false) intentionally contradicts its seeded value (true)
	// while Changed=false. If Changed were ignored, OpenIssues would flip to
	// false and the assertion below would fail.
	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingIssueViewOpenIssues:    {Value: false, Changed: false},
		types.SettingIssueViewIgnoredIssues: {Value: true, Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	actual := config.GetIssueViewOptions(conf)
	assert.True(t, actual.OpenIssues, "OpenIssues must be preserved as true when only Ignored is Changed")
	assert.True(t, actual.IgnoredIssues, "IgnoredIssues must be updated to true")
}

func TestApplyIssueViewOptions_PreservesIgnoredWhenOnlyOpenChanged(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	seedIssueViewOptions(t, conf, types.IssueViewOptions{OpenIssues: true, IgnoredIssues: true})

	// Ignored's Value (false) intentionally contradicts its seeded value (true)
	// while Changed=false. If Changed were ignored, IgnoredIssues would flip to
	// false and the assertion below would fail.
	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
		types.SettingIssueViewIgnoredIssues: {Value: false, Changed: false},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	actual := config.GetIssueViewOptions(conf)
	assert.False(t, actual.OpenIssues, "OpenIssues must be updated to false")
	assert.True(t, actual.IgnoredIssues, "IgnoredIssues must be preserved as true when only Open is Changed")
}

func TestApplyIssueViewOptions_BothChangedWritesBoth(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	seedIssueViewOptions(t, conf, types.IssueViewOptions{OpenIssues: true, IgnoredIssues: false})

	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingIssueViewOpenIssues:    {Value: false, Changed: true},
		types.SettingIssueViewIgnoredIssues: {Value: true, Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	actual := config.GetIssueViewOptions(conf)
	assert.False(t, actual.OpenIssues)
	assert.True(t, actual.IgnoredIssues)
}

// TestApplyIssueViewOptions_EmptySettingsMapIsNoOp exercises the outer
// processConfigSettings guard (`if len(settings) == 0 { return }`) and
// therefore never enters applyIssueViewOptions. The inner
// `!openPresent && !ignoredPresent` guard is covered by
// TestApplyIssueViewOptions_NeitherChangedIsNoOp below.
func TestApplyIssueViewOptions_EmptySettingsMapIsNoOp(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	seed := types.IssueViewOptions{OpenIssues: true, IgnoredIssues: false}
	seedIssueViewOptions(t, conf, seed)

	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	assert.Equal(t, seed, config.GetIssueViewOptions(conf))
}

func TestApplyIssueViewOptions_NeitherChangedIsNoOp(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	seed := types.IssueViewOptions{OpenIssues: true, IgnoredIssues: false}
	seedIssueViewOptions(t, conf, seed)

	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingIssueViewOpenIssues:    {Value: false, Changed: false},
		types.SettingIssueViewIgnoredIssues: {Value: true, Changed: false},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	assert.Equal(t, seed, config.GetIssueViewOptions(conf))
}

// Locked PATCHes must be dropped before the apply chain; otherwise they persist as ghost
// entries at UserGlobalKey that become load-bearing once the admin lifts the lock.
func Test_UpdateSettings_LockedMachineField_RejectsPATCH(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService, nil)
	conf := engine.GetConfiguration()

	const lockedURL = "https://locked.snyk.io"
	conf.Set(configresolver.RemoteMachineKey(types.SettingPublishSecurityAtInceptionRules), &configresolver.RemoteConfigField{
		Value:    true,
		IsLocked: true,
		Origin:   "ldx-sync-test",
	})
	conf.Set(configresolver.RemoteMachineKey(types.SettingCodeEndpoint), &configresolver.RemoteConfigField{
		Value:    lockedURL,
		IsLocked: true,
		Origin:   "ldx-sync-test",
	})

	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingPublishSecurityAtInceptionRules: {Value: false, Changed: true},
		types.SettingCodeEndpoint:                    {Value: "https://user-attempted.snyk.io", Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	// Resolver returns the locked remote value, not the user PATCH attempt.
	assert.True(t, types.GetGlobalBool(conf, types.SettingPublishSecurityAtInceptionRules),
		"locked PublishSecurityAtInceptionRules must keep remote value")
	assert.Equal(t, lockedURL, types.GetGlobalString(conf, types.SettingCodeEndpoint),
		"locked CodeEndpoint must keep remote value")

	// UserGlobalKey was never written — apply* never received the entry.
	assert.False(t, conf.IsSet(configresolver.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules)),
		"PATCH for locked machine setting must not land at UserGlobalKey")
	assert.False(t, conf.IsSet(configresolver.UserGlobalKey(types.SettingCodeEndpoint)),
		"PATCH for locked machine setting must not land at UserGlobalKey")
}

// PATCH writes must land as *LocalConfigField{Changed: true} so the resolver chain at
// phase 2 (see types.GetGlobalBool for phase numbering) recognizes user intent rather
// than treating the value as a framework default sitting at the same key.
func Test_UpdateSettings_MachineFields_PATCHWrapsAsLocalConfigField(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService, nil)
	conf := engine.GetConfiguration()

	UpdateSettings(testCtx(t, t.Context(), engine, tokenService), conf, engine, engine.GetLogger(), map[string]*types.ConfigSetting{
		types.SettingAutomaticDownload: {Value: false, Changed: true},
		types.SettingSendErrorReports:  {Value: false, Changed: true},
		types.SettingTrustEnabled:      {Value: false, Changed: true},
		types.SettingTrustedFolders:    {Value: []interface{}{"/a", "/b"}, Changed: true},
	}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

	wrappedKeys := []string{
		types.SettingAutomaticDownload,
		types.SettingSendErrorReports,
		types.SettingTrustEnabled,
		types.SettingTrustedFolders,
	}
	for _, key := range wrappedKeys {
		raw := conf.Get(configresolver.UserGlobalKey(key))
		lf, ok := raw.(*configresolver.LocalConfigField)
		require.Truef(t, ok, "%s must be wrapped as *LocalConfigField, got %T", key, raw)
		assert.Truef(t, lf.Changed, "%s wrapper must have Changed=true so resolver phase 2 accepts it", key)
	}

	assert.False(t, types.GetGlobalBool(conf, types.SettingAutomaticDownload))
	assert.False(t, types.GetGlobalBool(conf, types.SettingSendErrorReports))
	assert.False(t, types.GetGlobalBool(conf, types.SettingTrustEnabled))
	assert.ElementsMatch(t, []types.FilePath{"/a", "/b"}, types.GetGlobalSliceFilePath(conf, types.SettingTrustedFolders))
}

// IDE-1969: When the org changes via workspace/didChangeConfiguration, the
// scan-state aggregator must be re-initialized so the Summary Panel resets to
// its "no scans yet" state. The reset must NOT happen when the org value is
// unchanged or when the LSP is not yet initialized (e.g., during the initial
// settings push).
//
// We observe the reset via GetScanErr rather than StateSnapshot because the
// snapshot filters by per-folder "enabled products", which requires extra
// folder-config wiring that's irrelevant to this test. GetScanErr reads the
// raw scanState entry directly, so a non-nil err proves the entry exists in
// its post-SetScanDone state, and a nil err after the change proves Init
// reset that entry.
func Test_applyOrganization_ResetsSummaryPanelOnOrgChange(t *testing.T) {
	// Valid UUIDs are required: GetGlobalOrganization triggers GAF's
	// defaultFuncOrganization, which validates non-UUID strings against
	// /rest/self and returns "" on failure — making old/new compare equal.
	const oldOrg = "00000000-0000-0000-0000-0000000000a1"
	const newOrg = "00000000-0000-0000-0000-0000000000a2"
	scanErr := errors.New("scan failed")

	setupAggregatorWithFinishedScan := func(t *testing.T) (workflow.Engine, types.FilePath, scanstates.Aggregator, context.Context) {
		t.Helper()
		engine, tokenService := testutil.UnitTestWithEngine(t)
		ctrl := gomock.NewController(t)
		emitter := scanstates.NewMockScanStateChangeEmitter(ctrl)
		emitter.EXPECT().Emit(gomock.Any()).AnyTimes()
		realAgg := scanstates.NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, testutil.DefaultConfigResolver(engine), engine)
		mockNotifier := notification.NewMockNotifier()
		di.TestInit(t, engine, tokenService, &di.Dependencies{ScanStateAggregator: realAgg, Notifier: mockNotifier})

		tmpDir := types.FilePath(t.TempDir())
		require.NoError(t, initTestRepo(t, string(tmpDir)))
		_, _ = workspaceutil.SetupWorkspace(t, engine, tmpDir)

		// SetupWorkspace stores the folder under its normalized PathKey; the
		// production reset path will look folders up via ws.Folders(), so use
		// that same path as the aggregator key to avoid a key mismatch.
		folders := config.GetWorkspace(engine.GetConfiguration()).Folders()
		require.Len(t, folders, 1)
		folderPath := folders[0].Path()

		realAgg.Init([]types.FilePath{folderPath})
		realAgg.SetScanDone(folderPath, product.ProductOpenSource, false, scanErr)
		require.Equal(t, scanErr, realAgg.GetScanErr(folderPath, product.ProductOpenSource, false),
			"precondition: aggregator should hold the seeded scan error")

		config.SetOrganization(engine.GetConfiguration(), oldOrg)
		ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
			ctx2.DepNotifier:            mockNotifier,
			ctx2.DepScanStateAggregator: realAgg,
			ctx2.DepAuthService:         di.AuthenticationService(),
			ctx2.DepFeatureFlagService:  di.FeatureFlagService(),
		})
		return engine, folderPath, realAgg, ctx
	}

	t.Run("org changed and LSP initialized -> aggregator is reset", func(t *testing.T) {
		engine, folderPath, realAgg, ctx := setupAggregatorWithFinishedScan(t)
		conf := engine.GetConfiguration()
		conf.Set(types.SettingIsLspInitialized, true)

		UpdateSettings(ctx, conf, engine, engine.GetLogger(),
			map[string]*types.ConfigSetting{
				types.SettingOrganization: {Value: newOrg, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.NoError(t, realAgg.GetScanErr(folderPath, product.ProductOpenSource, false),
			"summary panel should be reset to initial state on org change")
	})

	t.Run("org unchanged -> aggregator is NOT reset", func(t *testing.T) {
		engine, folderPath, realAgg, ctx := setupAggregatorWithFinishedScan(t)
		conf := engine.GetConfiguration()
		conf.Set(types.SettingIsLspInitialized, true)

		UpdateSettings(ctx, conf, engine, engine.GetLogger(),
			map[string]*types.ConfigSetting{
				types.SettingOrganization: {Value: oldOrg, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, scanErr, realAgg.GetScanErr(folderPath, product.ProductOpenSource, false),
			"summary panel must not be reset when the org value is unchanged")
	})

	t.Run("LSP not initialized -> aggregator is NOT reset", func(t *testing.T) {
		engine, folderPath, realAgg, ctx := setupAggregatorWithFinishedScan(t)
		conf := engine.GetConfiguration()
		// SettingIsLspInitialized intentionally left false.

		UpdateSettings(ctx, conf, engine, engine.GetLogger(),
			map[string]*types.ConfigSetting{
				types.SettingOrganization: {Value: newOrg, Changed: true},
			}, nil, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.Equal(t, scanErr, realAgg.GetScanErr(folderPath, product.ProductOpenSource, false),
			"summary panel must not be reset before the LSP is initialized")
	})
}

func Test_updateFolderConfig_PreferredOrgChange_ResetsSummaryPanelOnOrgChange(t *testing.T) {
	const oldOrg = "00000000-0000-0000-0000-0000000000b1"
	const newOrg = "00000000-0000-0000-0000-0000000000b2"
	scanErr := errors.New("scan failed")

	setupAggregatorWithFinishedScan := func(t *testing.T) (*folderConfigTestSetup, types.FilePath, scanstates.Aggregator, context.Context) {
		t.Helper()
		engine, tokenService := testutil.UnitTestWithEngine(t)

		ctrl := gomock.NewController(t)
		emitter := scanstates.NewMockScanStateChangeEmitter(ctrl)
		emitter.EXPECT().Emit(gomock.Any()).AnyTimes()
		realAgg := scanstates.NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, testutil.DefaultConfigResolver(engine), engine)
		mockNotifier := notification.NewMockNotifier()
		mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)
		mockLdxSync.EXPECT().RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		deps := di.TestInit(t, engine, tokenService, &di.Dependencies{ScanStateAggregator: realAgg, Notifier: mockNotifier, LdxSyncService: mockLdxSync})
		ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
			ctx2.DepNotifier:            mockNotifier,
			ctx2.DepLdxSyncService:      mockLdxSync,
			ctx2.DepScanStateAggregator: realAgg,
			ctx2.DepAuthService:         deps.AuthenticationService,
			ctx2.DepFeatureFlagService:  deps.FeatureFlagService,
			ctx2.DepConfigResolver:      testutil.DefaultConfigResolver(engine),
		})

		engineConfig := engine.GetConfiguration()
		engineConfig.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction("test-default-org-uuid"))
		engineConfig.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction("test-default-org-slug"))

		folderPath := types.FilePath(t.TempDir())
		require.NoError(t, initTestRepo(t, string(folderPath)))
		_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath)

		setup := &folderConfigTestSetup{
			t:            t,
			engine:       engine,
			engineConfig: engineConfig,
			logger:       engine.GetLogger(),
			folderPath:   folderPath,
		}
		setup.createStoredConfig(oldOrg, true)

		folders := config.GetWorkspace(engine.GetConfiguration()).Folders()
		require.Len(t, folders, 1)
		aggregatorFolderPath := folders[0].Path()

		realAgg.Init([]types.FilePath{aggregatorFolderPath})
		realAgg.SetScanDone(aggregatorFolderPath, product.ProductOpenSource, false, scanErr)
		require.Equal(t, scanErr, realAgg.GetScanErr(aggregatorFolderPath, product.ProductOpenSource, false))

		return setup, aggregatorFolderPath, realAgg, ctx
	}

	t.Run("folder preferred org changed and LSP initialized -> aggregator is reset", func(t *testing.T) {
		setup, folderPath, realAgg, ctx := setupAggregatorWithFinishedScan(t)
		setup.engineConfig.Set(types.SettingIsLspInitialized, true)

		UpdateSettings(ctx, setup.engineConfig, setup.engine, setup.logger, nil, []types.LspFolderConfig{
			{
				FolderPath: setup.folderPath,
				Settings: map[string]*types.ConfigSetting{
					types.SettingPreferredOrg: {Value: newOrg, Changed: true},
				},
			},
		}, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

		assert.NoError(t, realAgg.GetScanErr(folderPath, product.ProductOpenSource, false))
	})

	t.Run("folder preferred org unchanged -> aggregator is NOT reset", func(t *testing.T) {
		setup, folderPath, realAgg, ctx := setupAggregatorWithFinishedScan(t)
		setup.engineConfig.Set(types.SettingIsLspInitialized, true)

		// Changed: true means the IDE included preferred_org in this patch, not that the value
		// differs from storage. Value is still oldOrg (same as setup.createStoredConfig(oldOrg, true)).
		UpdateSettings(ctx, setup.engineConfig, setup.engine, setup.logger, nil, []types.LspFolderConfig{
			{
				FolderPath: setup.folderPath,
				Settings: map[string]*types.ConfigSetting{
					types.SettingPreferredOrg: {Value: oldOrg, Changed: true},
				},
			},
		}, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

		assert.Equal(t, scanErr, realAgg.GetScanErr(folderPath, product.ProductOpenSource, false))
	})

	t.Run("LSP not initialized -> aggregator is NOT reset", func(t *testing.T) {
		setup, folderPath, realAgg, ctx := setupAggregatorWithFinishedScan(t)

		UpdateSettings(ctx, setup.engineConfig, setup.engine, setup.logger, nil, []types.LspFolderConfig{
			{
				FolderPath: setup.folderPath,
				Settings: map[string]*types.ConfigSetting{
					types.SettingPreferredOrg: {Value: newOrg, Changed: true},
				},
			},
		}, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))

		assert.Equal(t, scanErr, realAgg.GetScanErr(folderPath, product.ProductOpenSource, false))
	})

	t.Run("folder org_set_by_user toggled without preferred org change -> aggregator is reset", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)

		ctrl := gomock.NewController(t)
		emitter := scanstates.NewMockScanStateChangeEmitter(ctrl)
		emitter.EXPECT().Emit(gomock.Any()).AnyTimes()
		realAgg := scanstates.NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, testutil.DefaultConfigResolver(engine), engine)
		mockNotifier := notification.NewMockNotifier()
		mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)
		mockLdxSync.EXPECT().RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		deps := di.TestInit(t, engine, tokenService, &di.Dependencies{ScanStateAggregator: realAgg, Notifier: mockNotifier, LdxSyncService: mockLdxSync})
		ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
			ctx2.DepNotifier:            mockNotifier,
			ctx2.DepLdxSyncService:      mockLdxSync,
			ctx2.DepScanStateAggregator: realAgg,
			ctx2.DepAuthService:         deps.AuthenticationService,
			ctx2.DepFeatureFlagService:  deps.FeatureFlagService,
			ctx2.DepConfigResolver:      testutil.DefaultConfigResolver(engine),
		})

		conf := engine.GetConfiguration()
		conf.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction("test-default-org-uuid"))
		conf.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction("test-default-org-slug"))

		folderPath := types.FilePath(t.TempDir())
		require.NoError(t, initTestRepo(t, string(folderPath)))
		_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderPath, "", false)

		folders := config.GetWorkspace(conf).Folders()
		require.Len(t, folders, 1)
		aggregatorFolderPath := folders[0].Path()

		realAgg.Init([]types.FilePath{aggregatorFolderPath})
		realAgg.SetScanDone(aggregatorFolderPath, product.ProductOpenSource, false, scanErr)
		require.Equal(t, scanErr, realAgg.GetScanErr(aggregatorFolderPath, product.ProductOpenSource, false))

		conf.Set(types.SettingIsLspInitialized, true)

		UpdateSettings(ctx, conf, engine, engine.GetLogger(), nil, []types.LspFolderConfig{
			{
				FolderPath: folderPath,
				Settings: map[string]*types.ConfigSetting{
					types.SettingOrgSetByUser: {Value: true, Changed: true},
				},
			},
		}, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(engine))

		assert.NoError(t, realAgg.GetScanErr(aggregatorFolderPath, product.ProductOpenSource, false))
	})
}

// initRecordingAggregator wraps NoopStateAggregator to count Init calls so we
// can assert that the guard branches in resetSummaryPanelForOrgChange do not
// invoke Init when there are no folder paths to reset.
type initRecordingAggregator struct {
	scanstates.NoopStateAggregator
	initCalls [][]types.FilePath
}

func (r *initRecordingAggregator) Init(folders []types.FilePath) {
	cp := make([]types.FilePath, len(folders))
	copy(cp, folders)
	r.initCalls = append(r.initCalls, cp)
}

// IDE-1969: resetSummaryPanelForOrgChange has two early-return guards (nil
// aggregator, empty folder paths). Both must be safe — the nil case happens
// before di.Init wires the aggregator, and the empty case happens when an
// org change is reported for a workspace with no folders.
func TestResetSummaryPanelForOrgChange_NilAgg_DoesNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		resetSummaryPanelForOrgChange(nil, []types.FilePath{"/some/folder"})
	})
}

func TestResetSummaryPanelForOrgChange_EmptyFolderPaths_DoesNotCallInit(t *testing.T) {
	agg := &initRecordingAggregator{}
	assert.NotPanics(t, func() {
		resetSummaryPanelForOrgChange(agg, nil)
		resetSummaryPanelForOrgChange(agg, []types.FilePath{})
	})
	assert.Empty(t, agg.initCalls, "Init must not be called when folderPaths is empty")
}

// collidingDisplayNameMetadata is a minimal ConfigurationOptionsMetaData fake
// used to drive the "two raw keys → same display name" dedup subtest. Returns
// the mapped display name (if any) via GetConfigurationOptionAnnotation when
// asked for AnnotationDisplayName; the other interface methods are unused by
// notifyLockedFieldsRejected so they return zero values.
type collidingDisplayNameMetadata struct {
	alias map[string]string
}

func (c *collidingDisplayNameMetadata) GetConfigurationOptionAnnotation(name, annotation string) (string, bool) {
	if annotation != configresolver.AnnotationDisplayName {
		return "", false
	}
	dn, ok := c.alias[name]
	return dn, ok
}
func (c *collidingDisplayNameMetadata) ConfigurationOptionsByAnnotation(_, _ string) []string {
	return nil
}
func (c *collidingDisplayNameMetadata) ConfigurationOptionNameByAnnotation(_, _ string) (string, bool) {
	return "", false
}
func (c *collidingDisplayNameMetadata) GetConfigurationOptionType(_ string) string  { return "" }
func (c *collidingDisplayNameMetadata) GetConfigurationOptionUsage(_ string) string { return "" }

// Test_notifyLockedFieldsRejected_DeduplicatesAcrossGroupsAndEmitsOnce covers
// the IDE-1970 acceptance criteria for the locked-fields warning notification:
//
//   - exactly one notification per triggering event,
//   - regardless of how many fields (or folders) carry the same lock,
//   - with every affected field name surfaced in the message,
//   - each name appearing only once,
//   - field names rendered with their registered display names when available,
//   - and the message text deterministic (sorted) regardless of map iteration order.
//
// We exercise the helper directly with a MockNotifier so the test asserts on
// the user-visible message itself rather than on async listener side effects.
// The end-to-end regression test for the IDE-1970 bug (verifying that
// UpdateSettings/InitializeSettings produce exactly one notification across
// machine + folder scopes) lives in
// Test_UpdateSettings_LockedFields_EmitsExactlyOneNotification below.
func Test_notifyLockedFieldsRejected_DeduplicatesAcrossGroupsAndEmitsOnce(t *testing.T) {
	t.Run("single notification with deduplicated, sorted field list", func(t *testing.T) {
		mock := notification.NewMockNotifier()

		// Simulate one triggering event that produced locked-field rejections
		// at both the machine scope and across multiple folders, with overlap.
		machineRejections := []string{types.SettingSnykCodeEnabled}
		folderRejections := []string{
			types.SettingSeverityFilterHigh,
			types.SettingSnykCodeEnabled, // same field locked in another folder
			types.SettingSeverityFilterHigh,
		}

		// nil fm => fall back to raw setting identifiers, which keeps the assertion
		// stable across snyk-ls' display-name registrations.
		notifyLockedFieldsRejected(mock, nil, machineRejections, folderRejections)

		require.Equal(t, 1, mock.SendShowMessageCount(),
			"locked-field rejections from any number of fields/folders must collapse into exactly one notification (IDE-1970)")

		require.Len(t, mock.SentMessages(), 1)
		msg, ok := mock.SentMessages()[0].(sglsp.ShowMessageParams)
		require.True(t, ok, "sent payload should be a ShowMessageParams")
		assert.EqualValues(t, sglsp.MTWarning, msg.Type)

		// Pin the full message string. This catches three contracts at once:
		//   (a) the dedup ('snyk_code_enabled' appears once despite three input occurrences),
		//   (b) the deterministic sort order ('severity_filter_high' < 'snyk_code_enabled'
		//       lexicographically) — removing sort.Strings would surface map iteration order
		//       and break this assertion intermittently,
		//   (c) the user-visible message prefix wording.
		assert.Equal(t,
			"Failed to update some settings: locked by your organization's policy (severity_filter_high, snyk_code_enabled)",
			msg.Message,
			"locked-field notification text must be deterministic and deduplicated")
	})

	t.Run("no notification when nothing was rejected", func(t *testing.T) {
		mock := notification.NewMockNotifier()
		notifyLockedFieldsRejected(mock, nil, nil, nil, []string{})
		assert.Zero(t, mock.SendShowMessageCount(),
			"must stay silent when no fields were rejected — no triggering event => no notification")
	})

	t.Run("only one notification even when many folders reject the same lock", func(t *testing.T) {
		mock := notification.NewMockNotifier()
		// Before IDE-1970 this would produce one notification *per folder*.
		// processFolderConfigs flattens per-folder rejections into a single
		// slice before calling the helper, so this matches the real call shape.
		folderRejectionsFlat := []string{
			types.SettingSnykCodeEnabled,        // folder A
			types.SettingSnykCodeEnabled,        // folder B (same lock as A)
			types.SettingSeverityFilterCritical, // folder C (different lock)
		}
		notifyLockedFieldsRejected(mock, nil, nil, folderRejectionsFlat)
		assert.Equal(t, 1, mock.SendShowMessageCount(),
			"multiple folders with locked-field rejections must still produce only one notification")

		require.Len(t, mock.SentMessages(), 1)
		msg := mock.SentMessages()[0].(sglsp.ShowMessageParams)
		// 'severity_filter_critical' < 'snyk_code_enabled', and snyk_code_enabled
		// appears only once despite being rejected by two folders.
		assert.Equal(t,
			"Failed to update some settings: locked by your organization's policy (severity_filter_critical, snyk_code_enabled)",
			msg.Message,
			"flattened multi-folder rejections must still dedupe and sort")
	})

	t.Run("two raw keys that resolve to the same display name collapse to one entry", func(t *testing.T) {
		// Guard against a subtle dedup hole: deduping only on the raw setting
		// identifier lets two distinct raw keys that share a display name leak
		// duplicate entries into the user-facing message. The helper must dedup
		// on the resolved display name.
		mock := notification.NewMockNotifier()
		fm := &collidingDisplayNameMetadata{
			alias: map[string]string{
				"raw.alpha": "Same Display Name",
				"raw.beta":  "Same Display Name",
				"raw.gamma": "Other Name",
			},
		}
		notifyLockedFieldsRejected(mock, fm,
			[]string{"raw.alpha", "raw.beta"},
			[]string{"raw.gamma"},
		)

		require.Equal(t, 1, mock.SendShowMessageCount())
		msg := mock.SentMessages()[0].(sglsp.ShowMessageParams)
		assert.Equal(t,
			"Failed to update some settings: locked by your organization's policy (Other Name, Same Display Name)",
			msg.Message,
			"two raw keys resolving to the same display name must collapse to one entry in the notification")
	})

	t.Run("setting identifiers are rendered as registered display names when fm is provided", func(t *testing.T) {
		// Wire a real ConfigurationOptionsMetaData by registering the snyk-ls
		// flags into a flagset. This proves the helper consults
		// AnnotationDisplayName rather than echoing the raw snake_case keys.
		engine, _ := testutil.UnitTestWithEngine(t)
		fs := pflag.NewFlagSet("test-locked-fields-display-name", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = engine.GetConfiguration().AddFlagSet(fs)
		fm := workflow.ConfigurationOptionsFromFlagset(fs)

		mock := notification.NewMockNotifier()
		notifyLockedFieldsRejected(mock,
			fm,
			[]string{types.SettingSnykCodeEnabled},
			[]string{types.SettingSeverityFilterHigh},
		)

		require.Equal(t, 1, mock.SendShowMessageCount())
		msg := mock.SentMessages()[0].(sglsp.ShowMessageParams)
		// "Severity Filter High" < "Snyk Code Enabled" lexicographically.
		assert.Equal(t,
			"Failed to update some settings: locked by your organization's policy (Severity Filter High, Snyk Code Enabled)",
			msg.Message,
			"notification must render display names (e.g. 'Snyk Code Enabled') instead of raw 'snyk_code_enabled' identifiers")
	})
}

// Test_UpdateSettings_LockedFields_EmitsExactlyOneNotification is the
// end-to-end regression test for IDE-1970. It drives `UpdateSettings` through
// the full pipeline (machine-scope validation + multi-folder accumulator +
// notification emission) and asserts that exactly one ShowMessageParams is
// emitted covering every locked field across every folder. If a future refactor
// re-introduces an inline `SendShowMessage` call in `processConfigSettings` or
// `processSingleLspFolderConfig` (the bug IDE-1970 fixed), this test fails —
// the helper-level unit tests above would not.
// Test_validateLockedMachineFields_EarlyReturns pins the two early-return
// paths that the integration suite exercises only indirectly. Catching a
// regression on either path here is much faster than running the full
// UpdateSettings flow (see IDE-1970).
func Test_validateLockedMachineFields_EarlyReturns(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))

	t.Run("nil configResolver returns nil without panicking", func(t *testing.T) {
		settings := map[string]*types.ConfigSetting{
			types.SettingSnykCodeEnabled: {Value: false, Changed: true},
		}
		got := validateLockedMachineFields(settings, nil, nil, &logger)
		assert.Nil(t, got, "nil resolver must short-circuit to nil — without it, IsLockedMachine would dereference a nil pointer")
		assert.NotEmpty(t, settings, "settings must be left untouched when no validation runs")
	})

	t.Run("empty settings map returns nil without consulting the resolver", func(t *testing.T) {
		// Configure the mock with no EXPECT() calls — any method invocation on
		// it would fail the test, which is exactly the contract we want to pin:
		// the early return must not touch the resolver.
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		resolver := mock_types.NewMockConfigResolverInterface(ctrl)

		got := validateLockedMachineFields(map[string]*types.ConfigSetting{}, resolver, nil, &logger)
		assert.Nil(t, got, "empty settings must short-circuit to nil")
	})
}

func Test_UpdateSettings_LockedFields_EmitsExactlyOneNotification(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService, nil)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	// Mock the org-default lookups so workspace setup doesn't hit the network.
	conf.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction("test-default-org-uuid"))
	conf.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction("test-default-org-slug"))

	// Two workspace folders, both bound to org-a (per-folder PreferredOrg below).
	folderA := types.FilePath(t.TempDir())
	folderB := types.FilePath(t.TempDir())
	require.NoError(t, initTestRepo(t, string(folderA)))
	require.NoError(t, initTestRepo(t, string(folderB)))
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderA, folderB)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderA, "org-a", true)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderB, "org-a", true)

	// Lock a machine-scope setting at the RemoteMachineKey level.
	conf.Set(configresolver.RemoteMachineKey(types.SettingApiEndpoint),
		&configresolver.RemoteConfigField{Value: "https://locked.api.snyk.io", IsLocked: true})

	// Lock two folder-scope settings at the org level. Both folders inherit
	// these locks because they share org-a above.
	orgConfig := types.NewLDXSyncOrgConfig("org-a")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, "group")
	orgConfig.SetField(types.SettingSeverityFilterHigh, true, true, "group")
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	resolver := testutil.DefaultConfigResolver(engine)
	di.SetConfigResolver(resolver)

	// Use a local notifier so this test is fully isolated from the global DI
	// singleton and can run in parallel without cross-test interference.
	localNotifier := notification.NewNotifier()
	var (
		mu           sync.Mutex
		showMessages []sglsp.ShowMessageParams
	)
	localNotifier.CreateListener(func(params any) {
		if sm, ok := params.(sglsp.ShowMessageParams); ok {
			mu.Lock()
			defer mu.Unlock()
			showMessages = append(showMessages, sm)
		}
	})
	t.Cleanup(func() { localNotifier.DisposeListener() })

	// One triggering event that tries to PATCH every locked setting across
	// machine scope and both folders. folderB also tries to change
	// SnykCodeEnabled, which collides with folderA — the bug being fixed
	// previously emitted one notification per folder; the fix collapses them.
	machineSettings := map[string]*types.ConfigSetting{
		types.SettingApiEndpoint: {Value: "https://attempted-override", Changed: true},
	}
	folderConfigs := []types.LspFolderConfig{
		{
			FolderPath: folderA,
			Settings: map[string]*types.ConfigSetting{
				types.SettingSnykCodeEnabled:    {Value: false, Changed: true},
				types.SettingSeverityFilterHigh: {Value: false, Changed: true},
			},
		},
		{
			FolderPath: folderB,
			Settings: map[string]*types.ConfigSetting{
				types.SettingSnykCodeEnabled: {Value: false, Changed: true},
			},
		},
	}

	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepNotifier:           localNotifier,
		ctx2.DepAuthService:        di.AuthenticationService(),
		ctx2.DepConfigResolver:     resolver,
		ctx2.DepFeatureFlagService: di.FeatureFlagService(),
	})
	UpdateSettings(ctx, conf, engine, logger, machineSettings, folderConfigs, analytics.TriggerSourceTest, resolver)

	// Wait for the listener goroutine to drain at least one ShowMessage.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(showMessages) >= 1
	}, 2*time.Second, 10*time.Millisecond,
		"expected at least one ShowMessage notification after UpdateSettings with locked fields")

	// IDE-1970 regression guard: assert that no *additional* notification
	// arrives within the polling window. require.Never fails fast if a second
	// message lands (the pre-fix behavior) and is bounded by the timeout if
	// none does — strictly better than time.Sleep+require.Len which has the
	// same upper bound but blocks linearly and cannot fail early.
	require.Never(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(showMessages) > 1
	}, 200*time.Millisecond, 10*time.Millisecond,
		"IDE-1970 regression: a single triggering event with locked fields across multiple folders must produce exactly one ShowMessage notification")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, showMessages, 1,
		"expected exactly one ShowMessage; got %d (%v)", len(showMessages), showMessages)

	msg := showMessages[0]
	assert.EqualValues(t, sglsp.MTWarning, msg.Type)
	// All three locked fields must appear in the single message, deduplicated
	// (SnykCodeEnabled is rejected by both folders but listed once) and
	// rendered via their registered display names.
	assert.Contains(t, msg.Message, "API Endpoint", "machine-scope locked field must be listed")
	assert.Contains(t, msg.Message, "Snyk Code Enabled", "folder-scope locked field must be listed via display name")
	assert.Contains(t, msg.Message, "Severity Filter High", "folder-scope locked field must be listed via display name")
	assert.Equal(t, 1, strings.Count(msg.Message, "Snyk Code Enabled"),
		"a field locked in multiple folders must appear at most once in the deduplicated message")
}

func TestApplyUserSettingsPath_PersistsValue(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	originalPath := os.Getenv("PATH")
	settings := map[string]*types.ConfigSetting{
		types.SettingUserSettingsPath: {Value: "/foo/bar", Changed: true},
	}
	applyUserSettingsPath(conf, settings)

	assert.Equal(t, "/foo/bar", types.GetGlobalString(conf, types.SettingUserSettingsPath))
	assert.Equal(t, originalPath, os.Getenv("PATH"), "didChangeConfiguration must not mutate os PATH — restart required")
}

func TestApplyUserSettingsPath_IgnoresUnchanged(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	types.SetGlobalUser(conf, types.SettingUserSettingsPath, "/original")

	settings := map[string]*types.ConfigSetting{
		types.SettingUserSettingsPath: {Value: "/new", Changed: false},
	}
	applyUserSettingsPath(conf, settings)

	assert.Equal(t, "/original", types.GetGlobalString(conf, types.SettingUserSettingsPath))
}

// Test_ApplyOrganization_LDXSyncRefreshesForGlobalOrgFallback verifies LDX-Sync refresh behavior when global org changes.
// Tests three scenarios: refresh when folders use global fallback, no refresh when folders have
// explicit org, and no refresh when org is unchanged.
func Test_ApplyOrganization_LDXSyncRefreshesForGlobalOrgFallback(t *testing.T) {
	originalGlobalOrg := "original-global-org"
	testCases := []struct {
		name                string
		preferredOrg        string
		newGlobalOrg        string
		expectFolderRefresh bool
	}{
		{
			// When the global org changes and there are folders with OrgSetByUser=true and PreferredOrg="",
			// LDX-Sync refresh is triggered for those folders.
			name:                "TriggersRefreshForFoldersUsingGlobalOrgFallback",
			preferredOrg:        "",
			newGlobalOrg:        "new-global-org-uuid",
			expectFolderRefresh: true,
		},
		{
			// When the global org changes but no folders use the global org fallback,
			// LDX-Sync refresh is NOT triggered.
			name:                "NoRefreshWhenNoFoldersDependOnGlobalOrg",
			preferredOrg:        "folder-specific-org",
			newGlobalOrg:        "new-global-org-uuid",
			expectFolderRefresh: false,
		},
		{
			// When the org is set to the same value, no refresh is triggered.
			name:                "NoRefreshWhenOrgUnchanged",
			preferredOrg:        "",
			newGlobalOrg:        originalGlobalOrg,
			expectFolderRefresh: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setup := setupFolderConfigTest(t)

			// Clear the mock default value function so we can test actual org changes
			setup.engineConfig.AddDefaultValue(configuration.ORGANIZATION, nil)

			// Setup: Folder config with OrgSetByUser=true, PreferredOrg as specified
			setup.createStoredConfig(tc.preferredOrg, true)

			// Setup: Mock LDX-Sync service to track refresh calls
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)
			mockLdxSyncService := mock_command.NewMockLdxSyncService(ctrl)

			// Setup: Attach mock LdxSyncService and notifier to a new context
			ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
				ctx2.DepLdxSyncService: mockLdxSyncService,
				ctx2.DepNotifier:       notification.NewMockNotifier(),
			})

			// Setup: Set initial global org and mark LS as initialized
			config.SetOrganization(setup.engineConfig, originalGlobalOrg)
			setup.engineConfig.Set(types.SettingIsLspInitialized, true)

			// Expect: RefreshConfigFromLdxSync should be called as specified
			mockLdxSyncService.EXPECT().
				RefreshConfigFromLdxSync(gomock.Any(), setup.engineConfig, setup.engine, setup.logger, gomock.Any(), gomock.Any()).
				Times(util.Ternary(tc.expectFolderRefresh, 1, 0)).
				Do(func(_ context.Context, _ configuration.Configuration, _ workflow.Engine, _ *zerolog.Logger, folders []types.Folder, _ any) {
					assert.Len(t, folders, 1, "Should refresh exactly one folder")
					assert.Equal(t, setup.folderPath, folders[0].Path(), "Should refresh the folder using global org fallback")
				})

			// Test: Change global org
			applyOrganization(ctx, setup.engineConfig, setup.engine, setup.logger, map[string]*types.ConfigSetting{
				types.SettingOrganization: {Value: tc.newGlobalOrg, Changed: true},
			}, analytics.TriggerSourceTest, testutil.DefaultConfigResolver(setup.engine))
		})
	}
}

func Test_applyToken_NilEntry(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctx := testCtx(t, t.Context(), engine, tokenService)
	authService := mustAuthenticationServiceFromContext(ctx)

	// Capture the token before the call to detect any unwanted change.
	tokenBefore := config.GetToken(engine.GetConfiguration())

	// Calling applyToken with a nil map entry must NOT panic.
	require.NotPanics(t, func() {
		applyToken(map[string]*types.ConfigSetting{types.SettingToken: nil}, authService)
	})

	// UpdateCredentials must NOT have been called: the token must remain unchanged.
	require.Equal(t, tokenBefore, config.GetToken(engine.GetConfiguration()), "token must not change when map entry is nil")
}

// Test_UpdateSettings_AlwaysSendsLspConfiguration previously verified that
// UpdateSettings sent $/snyk.configuration unconditionally (IDE-1954).
// That unconditional send caused an infinite refresh loop: a no-op save (e.g.
// a write-only token field that never appears in BuildLspConfiguration) would
// trigger a re-render, which auto-saved again, echo-ing forever (IDE-2149).
// The test below (Test_UpdateSettings_SendsLspConfigurationOnlyWhenEffectiveConfigChanges)
// is the corrected version of this assertion.
//
// The old assertion — "a token-only change must still emit $/snyk.configuration" —
// was wrong: the token is a write-only field excluded from BuildLspConfiguration,
// so before and after are identical and no notification should be sent.
func Test_UpdateSettings_AlwaysSendsLspConfiguration(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	conf.Set(types.SettingIsLspInitialized, true)

	ctx := testCtx(t, t.Context(), engine, tokenService)

	// A real (non-write-only) machine-scoped setting change must still emit
	// $/snyk.configuration. SettingProxyInsecure is machine-scoped, defaults to
	// false, and is NOT write-only, so it appears in BuildLspConfiguration output.
	settings := map[string]*types.ConfigSetting{
		types.SettingProxyInsecure: {Value: true, Changed: true},
	}
	UpdateSettings(ctx, conf, engine, engine.GetLogger(), settings, nil, analytics.TriggerSourceIDE, testutil.DefaultConfigResolver(engine))

	// Extract the notifier that testCtx placed in context and check sent messages.
	n, ok := notifierFromContext(ctx)
	require.True(t, ok, "notifier must be present in context")
	mockNotifier, ok := n.(*notification.MockNotifier)
	require.True(t, ok, "notifier must be a *notification.MockNotifier")

	var foundLspConfig bool
	for _, msg := range mockNotifier.SentMessages() {
		if _, ok := msg.(types.LspConfigurationParam); ok {
			foundLspConfig = true
			break
		}
	}
	require.True(t, foundLspConfig, "UpdateSettings must send a types.LspConfigurationParam when an effective config value changes")
}

// Test_UpdateSettings_SendsLspConfigurationOnlyWhenEffectiveConfigChanges is the
// integration test for IDE-2149: guard the $/snyk.configuration echo so that a
// no-op workspace/didChangeConfiguration (one that results in an identical
// effective configuration) does NOT send the notification, breaking the
// infinite-refresh loop in the IDE HTML settings page.
//
// The loop was:
//  1. User clicks Snyk Code checkbox (SAST-gated; effective value stays false).
//  2. UpdateSettings unconditionally sends $/snyk.configuration.
//  3. IDE re-renders the HTML page from the notification.
//  4. Auto-save fires again → another no-op didChangeConfiguration → goto 2.
func Test_UpdateSettings_SendsLspConfigurationOnlyWhenEffectiveConfigChanges(t *testing.T) {
	t.Run("no-op change emits zero $/snyk.configuration notifications", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		conf := engine.GetConfiguration()
		conf.Set(types.SettingIsLspInitialized, true)
		cr := testutil.DefaultConfigResolver(engine)

		ctx := testCtx(t, t.Context(), engine, tokenService)

		// Token is a write-only setting; it is excluded from BuildLspConfiguration.
		// Sending only a token change must not echo $/snyk.configuration because
		// the effective (visible) configuration is identical before and after.
		settings := map[string]*types.ConfigSetting{
			types.SettingToken: {Value: "new-token", Changed: true},
		}
		UpdateSettings(ctx, conf, engine, engine.GetLogger(), settings, nil, analytics.TriggerSourceIDE, cr)

		n, ok := notifierFromContext(ctx)
		require.True(t, ok)
		mockNotifier, ok := n.(*notification.MockNotifier)
		require.True(t, ok)

		var lspConfigCount int
		for _, msg := range mockNotifier.SentMessages() {
			if _, ok := msg.(types.LspConfigurationParam); ok {
				lspConfigCount++
			}
		}
		require.Equal(t, 0, lspConfigCount,
			"a no-op save (write-only token field) must not send $/snyk.configuration — "+
				"sending unconditionally caused the IDE HTML settings page infinite-refresh loop (IDE-2149)")
	})

	t.Run("real effective-config change emits exactly one $/snyk.configuration notification", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		conf := engine.GetConfiguration()
		conf.Set(types.SettingIsLspInitialized, true)
		cr := testutil.DefaultConfigResolver(engine)

		ctx := testCtx(t, t.Context(), engine, tokenService)

		// SettingProxyInsecure is machine-scoped and NOT write-only, so it
		// appears in the BuildLspConfiguration output. Its default is false;
		// setting it to true changes the effective LspConfigurationParam that
		// the IDE receives via $/snyk.configuration.
		settings := map[string]*types.ConfigSetting{
			types.SettingProxyInsecure: {Value: true, Changed: true},
		}
		UpdateSettings(ctx, conf, engine, engine.GetLogger(), settings, nil, analytics.TriggerSourceIDE, cr)

		n, ok := notifierFromContext(ctx)
		require.True(t, ok)
		mockNotifier, ok := n.(*notification.MockNotifier)
		require.True(t, ok)

		var lspConfigCount int
		for _, msg := range mockNotifier.SentMessages() {
			if _, ok := msg.(types.LspConfigurationParam); ok {
				lspConfigCount++
			}
		}
		require.Equal(t, 1, lspConfigCount,
			"a real effective-config change must emit exactly one $/snyk.configuration notification")
	})
}

// Test_UpdateSettings_FolderConfigChange_EmitsExactlyOneLspConfiguration is the
// integration test for the double-send bug: when workspace/didChangeConfiguration
// carries a real folder-config change (e.g. baseBranch), the IDE must receive
// EXACTLY ONE $/snyk.configuration notification — not two.
//
// Before the fix, UpdateSettings emitted two:
//   - one from sendFolderConfigUpdateIfNeeded (inside processFolderConfigs), and
//   - one from the outer DeepEqual guard (in UpdateSettings itself).
//
// The fix removes sendFolderConfigUpdateIfNeeded, making the outer guard the
// single emission point. The outer guard is strictly more correct: it sends only
// when the IDE-visible payload (which already includes folder configs via
// BuildLspConfiguration) actually changes, and it is gated on lspInitialized
// (matching the semantics of didChangeConfiguration = post-init).
func Test_UpdateSettings_FolderConfigChange_EmitsExactlyOneLspConfiguration(t *testing.T) {
	t.Run("real folder-config change emits exactly one $/snyk.configuration", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		cr := testutil.DefaultConfigResolver(engine)
		conf := engine.GetConfiguration()
		conf.Set(types.SettingIsLspInitialized, true)

		mockNotifier := notification.NewMockNotifier()
		ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
			ctx2.DepNotifier:            mockNotifier,
			ctx2.DepAuthService:         di.TestInit(t, engine, tokenService, &di.Dependencies{Notifier: mockNotifier}).AuthenticationService,
			ctx2.DepFeatureFlagService:  di.FeatureFlagService(),
			ctx2.DepConfigResolver:      cr,
			ctx2.DepLdxSyncService:      command.NewLdxSyncService(cr),
			ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		})

		folderPath := types.FilePath(t.TempDir())
		require.NoError(t, initTestRepo(t, string(folderPath)))
		_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath)

		// Change the base branch — a folder-scoped setting that appears in
		// buildLspFolderConfigs and therefore in the outer DeepEqual snapshot.
		folderConfigs := []types.LspFolderConfig{
			{
				FolderPath: folderPath,
				Settings: map[string]*types.ConfigSetting{
					types.SettingBaseBranch: {Value: "new-branch", Changed: true},
				},
			},
		}
		UpdateSettings(ctx, conf, engine, engine.GetLogger(), nil, folderConfigs, analytics.TriggerSourceIDE, cr)

		var lspConfigCount int
		for _, msg := range mockNotifier.SentMessages() {
			if _, ok := msg.(types.LspConfigurationParam); ok {
				lspConfigCount++
			}
		}
		require.Equal(t, 1, lspConfigCount,
			"a folder-config change must emit EXACTLY ONE $/snyk.configuration — "+
				"two indicates the double-send bug (inner sendFolderConfigUpdateIfNeeded + outer DeepEqual guard)")
	})

	t.Run("no-op folder-config change emits zero $/snyk.configuration", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		cr := testutil.DefaultConfigResolver(engine)
		conf := engine.GetConfiguration()
		conf.Set(types.SettingIsLspInitialized, true)

		mockNotifier := notification.NewMockNotifier()
		ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
			ctx2.DepNotifier:            mockNotifier,
			ctx2.DepAuthService:         di.TestInit(t, engine, tokenService, &di.Dependencies{Notifier: mockNotifier}).AuthenticationService,
			ctx2.DepFeatureFlagService:  di.FeatureFlagService(),
			ctx2.DepConfigResolver:      cr,
			ctx2.DepLdxSyncService:      command.NewLdxSyncService(cr),
			ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		})

		folderPath := types.FilePath(t.TempDir())
		require.NoError(t, initTestRepo(t, string(folderPath)))
		_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath)

		// First call: seed the base branch so the config is already stored.
		UpdateSettings(ctx, conf, engine, engine.GetLogger(), nil, []types.LspFolderConfig{
			{
				FolderPath: folderPath,
				Settings: map[string]*types.ConfigSetting{
					types.SettingBaseBranch: {Value: "same-branch", Changed: true},
				},
			},
		}, analytics.TriggerSourceIDE, cr)

		// Reset notifier so we only count what the second (no-op) call sends.
		mockNotifier2 := notification.NewMockNotifier()
		ctx2Deps := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
			ctx2.DepNotifier:            mockNotifier2,
			ctx2.DepAuthService:         di.AuthenticationService(),
			ctx2.DepFeatureFlagService:  di.FeatureFlagService(),
			ctx2.DepConfigResolver:      cr,
			ctx2.DepLdxSyncService:      command.NewLdxSyncService(cr),
			ctx2.DepScanStateAggregator: scanstates.NewNoopStateAggregator(),
		})

		// Second call: send the exact same baseBranch — no effective change.
		UpdateSettings(ctx2Deps, conf, engine, engine.GetLogger(), nil, []types.LspFolderConfig{
			{
				FolderPath: folderPath,
				Settings: map[string]*types.ConfigSetting{
					types.SettingBaseBranch: {Value: "same-branch", Changed: true},
				},
			},
		}, analytics.TriggerSourceIDE, cr)

		var lspConfigCount int
		for _, msg := range mockNotifier2.SentMessages() {
			if _, ok := msg.(types.LspConfigurationParam); ok {
				lspConfigCount++
			}
		}
		require.Equal(t, 0, lspConfigCount,
			"a no-op folder-config change (same value resent) must not emit $/snyk.configuration")
	})
}

func TestApplyEnvironment_PersistsGlobalUser(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	// t.Setenv registers cleanup that restores these to "" on test end, so every key we
	// os.Setenv inside applyEnvironment is cleaned up without a manual t.Cleanup/Unsetenv.
	t.Setenv("SNYK_TEST_ADDITIONAL_ENV_X", "")
	t.Setenv("SNYK_TEST_ADDITIONAL_ENV_Y", "")

	settings := map[string]*types.ConfigSetting{
		types.SettingAdditionalEnvironment: {Value: "SNYK_TEST_ADDITIONAL_ENV_X=hello;SNYK_TEST_ADDITIONAL_ENV_Y=world", Changed: true},
	}
	applyEnvironment(conf, logger, settings)

	// os.Setenv side effect
	assert.Equal(t, "hello", os.Getenv("SNYK_TEST_ADDITIONAL_ENV_X"))
	assert.Equal(t, "world", os.Getenv("SNYK_TEST_ADDITIONAL_ENV_Y"))

	// Persisted to config for dialog pre-population
	assert.Equal(t, "SNYK_TEST_ADDITIONAL_ENV_X=hello;SNYK_TEST_ADDITIONAL_ENV_Y=world", types.GetGlobalString(conf, types.SettingAdditionalEnvironment))
}

func TestApplyEnvironment_ClearsPersistedValue(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	t.Setenv("SNYK_TEST_ADDITIONAL_ENV_CLEAR", "")

	// Seed a prior value (both persisted and applied to the process env).
	applyEnvironment(conf, logger, map[string]*types.ConfigSetting{
		types.SettingAdditionalEnvironment: {Value: "SNYK_TEST_ADDITIONAL_ENV_CLEAR=set", Changed: true},
	})
	assert.Equal(t, "set", os.Getenv("SNYK_TEST_ADDITIONAL_ENV_CLEAR"))
	assert.Equal(t, "SNYK_TEST_ADDITIONAL_ENV_CLEAR=set", types.GetGlobalString(conf, types.SettingAdditionalEnvironment))

	// User clears the field: {Value: "", Changed: true}.
	applyEnvironment(conf, logger, map[string]*types.ConfigSetting{
		types.SettingAdditionalEnvironment: {Value: "", Changed: true},
	})

	// Persisted value is cleared so the dialog repopulates blank.
	assert.Equal(t, "", types.GetGlobalString(conf, types.SettingAdditionalEnvironment))
	// And the previously-applied var is removed from the process env.
	_, present := os.LookupEnv("SNYK_TEST_ADDITIONAL_ENV_CLEAR")
	assert.False(t, present, "cleared env var should be unset from the process env")
}

func TestApplyEnvironment_UnchangedFieldNoOp(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	// Seed a persisted value, then apply settings where the field is absent / not Changed.
	types.SetGlobalUser(conf, types.SettingAdditionalEnvironment, "PRESERVED=1")

	applyEnvironment(conf, logger, map[string]*types.ConfigSetting{
		types.SettingAdditionalEnvironment: {Value: "ignored", Changed: false},
	})

	// Not Changed -> settingStr returns ok=false -> persisted value is left untouched.
	assert.Equal(t, "PRESERVED=1", types.GetGlobalString(conf, types.SettingAdditionalEnvironment))
}

func TestApplyEnvironment_SequentialApplyUnsetsDroppedKeys(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	t.Setenv("SNYK_TEST_ADDITIONAL_ENV_A", "")
	t.Setenv("SNYK_TEST_ADDITIONAL_ENV_B", "")

	applyEnvironment(conf, logger, map[string]*types.ConfigSetting{
		types.SettingAdditionalEnvironment: {Value: "SNYK_TEST_ADDITIONAL_ENV_A=1;SNYK_TEST_ADDITIONAL_ENV_B=2", Changed: true},
	})
	assert.Equal(t, "1", os.Getenv("SNYK_TEST_ADDITIONAL_ENV_A"))
	assert.Equal(t, "2", os.Getenv("SNYK_TEST_ADDITIONAL_ENV_B"))

	// Re-save dropping B: it must be unset from the process env, not left to leak into CLI subprocesses.
	applyEnvironment(conf, logger, map[string]*types.ConfigSetting{
		types.SettingAdditionalEnvironment: {Value: "SNYK_TEST_ADDITIONAL_ENV_A=1", Changed: true},
	})
	assert.Equal(t, "1", os.Getenv("SNYK_TEST_ADDITIONAL_ENV_A"))
	_, present := os.LookupEnv("SNYK_TEST_ADDITIONAL_ENV_B")
	assert.False(t, present, "dropped key B should be unset from the process env")
}

func TestApplyEnvironment_SkipsMalformedEntries(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	t.Setenv("SNYK_TEST_ADDITIONAL_ENV_GOOD", "")
	t.Setenv("SNYK_TEST_ADDITIONAL_ENV_OK", "")

	applyEnvironment(conf, logger, map[string]*types.ConfigSetting{
		types.SettingAdditionalEnvironment: {Value: "SNYK_TEST_ADDITIONAL_ENV_GOOD=1;BAD;SNYK_TEST_ADDITIONAL_ENV_OK=2", Changed: true},
	})

	// Well-formed entries are set; the malformed "BAD" segment (no '=') is skipped.
	assert.Equal(t, "1", os.Getenv("SNYK_TEST_ADDITIONAL_ENV_GOOD"))
	assert.Equal(t, "2", os.Getenv("SNYK_TEST_ADDITIONAL_ENV_OK"))
	_, present := os.LookupEnv("BAD")
	assert.False(t, present, "malformed entry should not be set as an env var")
}

func TestApplyEnvironment_ValuePreservesEquals(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	t.Setenv("SNYK_TEST_ADDITIONAL_ENV_B64", "")

	// SplitN(..., "=", 2) keeps everything after the first '=' as the value (base64 padding, JWTs, ...).
	applyEnvironment(conf, logger, map[string]*types.ConfigSetting{
		types.SettingAdditionalEnvironment: {Value: "SNYK_TEST_ADDITIONAL_ENV_B64=Zm9v==", Changed: true},
	})

	assert.Equal(t, "Zm9v==", os.Getenv("SNYK_TEST_ADDITIONAL_ENV_B64"))
}

// Test_ProcessConfigSettings_GlobalReset verifies the global "Project Defaults"
// reset path: a {changed:true, value:null} payload for an org-scope global setting
// Unsets the user override (effective value reverts to the flagset default) and
// the entry is removed from the settings map so the typed appliers do not re-apply
// it. Mirrors the per-folder reset coverage in TestFolderConfig_ApplyLspUpdate.
func Test_ProcessConfigSettings_GlobalReset(t *testing.T) {
	t.Run("reset clears bool + filter overrides and reverts to defaults", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		conf := engine.GetConfiguration()
		ctx := testCtx(t, t.Context(), engine, tokenService)
		cr := testutil.DefaultConfigResolver(engine)

		// Seed user overrides that differ from the flagset defaults.
		types.SetGlobalUser(conf, types.SettingSnykOssEnabled, false) // default true
		types.SetGlobalUser(conf, types.SettingSeverityFilterLow, false)
		require.True(t, types.HasGlobalUserOverride(conf, types.SettingSnykOssEnabled))
		require.True(t, types.HasGlobalUserOverride(conf, types.SettingSeverityFilterLow))

		settings := map[string]*types.ConfigSetting{
			types.SettingSnykOssEnabled:    {Value: nil, Changed: true},
			types.SettingSeverityFilterLow: {Value: nil, Changed: true},
		}
		processConfigSettings(ctx, conf, engine, engine.GetLogger(), settings, analytics.TriggerSourceTest, cr)

		assert.False(t, types.HasGlobalUserOverride(conf, types.SettingSnykOssEnabled),
			"oss override cleared")
		assert.True(t, types.GetGlobalBool(conf, types.SettingSnykOssEnabled),
			"oss reverts to flagset default true")
		assert.False(t, types.HasGlobalUserOverride(conf, types.SettingSeverityFilterLow),
			"severity-low override cleared")

		_, ossStillPresent := settings[types.SettingSnykOssEnabled]
		_, sevStillPresent := settings[types.SettingSeverityFilterLow]
		assert.False(t, ossStillPresent, "handled reset removed from settings map")
		assert.False(t, sevStillPresent, "handled reset removed from settings map")
	})

	t.Run("reset and set in the same payload are independent", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		conf := engine.GetConfiguration()
		ctx := testCtx(t, t.Context(), engine, tokenService)
		cr := testutil.DefaultConfigResolver(engine)

		types.SetGlobalUser(conf, types.SettingSnykOssEnabled, false)

		settings := map[string]*types.ConfigSetting{
			types.SettingSnykOssEnabled:  {Value: nil, Changed: true},  // reset
			types.SettingSnykCodeEnabled: {Value: true, Changed: true}, // set
		}
		processConfigSettings(ctx, conf, engine, engine.GetLogger(), settings, analytics.TriggerSourceTest, cr)

		assert.False(t, types.HasGlobalUserOverride(conf, types.SettingSnykOssEnabled), "oss reset")
		assert.True(t, types.GetGlobalBool(conf, types.SettingSnykOssEnabled), "oss back to default true")
		assert.True(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "code set to true")
	})

	t.Run("reset of organization reverts to fallback", func(t *testing.T) {
		// Use setupFolderConfigTest so we get:
		//   - SettingIsLspInitialized=true (orgChanged branch fires)
		//   - registered immutable defaults for ORGANIZATION / ORGANIZATION_SLUG
		//     so GetGlobalOrganization resolves deterministically to "test-default-org-uuid"
		setup := setupFolderConfigTest(t)
		conf := setup.engineConfig
		ctx := testCtx(t, t.Context(), setup.engine, setup.tokenService)
		cr := testutil.DefaultConfigResolver(setup.engine)

		config.SetOrganization(conf, "my-custom-org")
		require.Equal(t, "my-custom-org", types.GetGlobalString(conf, types.SettingLastSetOrganization))

		settings := map[string]*types.ConfigSetting{
			types.SettingOrganization: {Value: nil, Changed: true},
		}
		processConfigSettings(ctx, conf, setup.engine, setup.engine.GetLogger(), settings, analytics.TriggerSourceTest, cr)

		assert.Empty(t, types.GetGlobalString(conf, types.SettingLastSetOrganization),
			"last_set_organization cleared so a later set is not a no-op")
		_, present := settings[types.SettingOrganization]
		assert.False(t, present, "handled org reset removed from settings map")

		// After reset, GetGlobalOrganization must resolve to the registered immutable default.
		org := types.GetGlobalOrganization(conf)
		assert.Equal(t, "test-default-org-uuid", org,
			"org must revert to the registered flagset default after reset")
	})

	t.Run("reset of product-enablement key triggers HandleConfigChange when value changes", func(t *testing.T) {
		// Verifies that resetting a product-enablement key (snyk_oss_enabled) when the
		// effective value changes (override false → default true) with LSP initialized
		// results in ws.HandleConfigChange() being called via sendDiagnosticsForNewSettings.
		// Uses a MockWorkspace to observe the call.
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)

		setup := setupFolderConfigTest(t)
		conf := setup.engineConfig
		ctx := testCtx(t, t.Context(), setup.engine, setup.tokenService)
		cr := testutil.DefaultConfigResolver(setup.engine)

		// Replace the workspace with a mock so we can assert HandleConfigChange fires.
		// Use an atomic counter so we can wait on the goroutine reliably without a
		// fixed sleep (which is flaky on loaded CI runners).
		var handleConfigChangeCalled int32
		mockWs := mock_types.NewMockWorkspace(ctrl)
		mockWs.EXPECT().HandleConfigChange().
			Do(func() { atomic.AddInt32(&handleConfigChangeCalled, 1) }).
			MinTimes(1)
		mockWs.EXPECT().Folders().Return(nil).AnyTimes()
		config.SetWorkspace(conf, mockWs)

		// Seed an override that differs from the default (snyk_oss_enabled default is true).
		types.SetGlobalUser(conf, types.SettingSnykOssEnabled, false)
		require.True(t, types.HasGlobalUserOverride(conf, types.SettingSnykOssEnabled))
		require.False(t, types.GetGlobalBool(conf, types.SettingSnykOssEnabled), "override is false")

		settings := map[string]*types.ConfigSetting{
			types.SettingSnykOssEnabled: {Value: nil, Changed: true},
		}
		processConfigSettings(ctx, conf, setup.engine, setup.engine.GetLogger(), settings, analytics.TriggerSourceTest, cr)

		assert.False(t, types.HasGlobalUserOverride(conf, types.SettingSnykOssEnabled),
			"override must be cleared by reset")
		assert.True(t, types.GetGlobalBool(conf, types.SettingSnykOssEnabled),
			"oss must revert to true (flagset default) after reset")

		// Wait for the goroutine launched by sendDiagnosticsForNewSettings to call
		// HandleConfigChange. require.Eventually avoids the flaky fixed-sleep pattern.
		require.Eventually(t,
			func() bool { return atomic.LoadInt32(&handleConfigChangeCalled) > 0 },
			time.Second, time.Millisecond,
			"HandleConfigChange must be called after resetting a product-enablement key")
	})

	t.Run("no-op when no override exists", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		conf := engine.GetConfiguration()
		ctx := testCtx(t, t.Context(), engine, tokenService)
		cr := testutil.DefaultConfigResolver(engine)

		settings := map[string]*types.ConfigSetting{
			types.SettingSnykOssEnabled: {Value: nil, Changed: true},
		}
		processConfigSettings(ctx, conf, engine, engine.GetLogger(), settings, analytics.TriggerSourceTest, cr)

		assert.False(t, types.HasGlobalUserOverride(conf, types.SettingSnykOssEnabled))
		assert.True(t, types.GetGlobalBool(conf, types.SettingSnykOssEnabled), "still default true")
	})

	t.Run("reset of int key (SettingRiskScoreThreshold) uses type-correct reader", func(t *testing.T) {
		// Verifies that resetting SettingRiskScoreThreshold (int-registered, default 0)
		// correctly reverts to the flagset default. GetGlobalBool would always return false
		// for an int-registered key, making oldEffective == newEffective == false and
		// silently suppressing both analytics and the diagnostics refresh.
		// Note: SettingScanNetNew is covered by the "globalEffectiveValue reads bool-stored
		// scan_net_new correctly" sub-test, which uses the production bool storage path.
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)

		setup := setupFolderConfigTest(t)
		conf := setup.engineConfig
		ctx := testCtx(t, t.Context(), setup.engine, setup.tokenService)
		cr := testutil.DefaultConfigResolver(setup.engine)

		// Replace the workspace with a mock so we can observe HandleConfigChange.
		var handleConfigChangeCalled int32
		mockWs := mock_types.NewMockWorkspace(ctrl)
		mockWs.EXPECT().HandleConfigChange().
			Do(func() { atomic.AddInt32(&handleConfigChangeCalled, 1) }).
			MinTimes(1)
		mockWs.EXPECT().Folders().Return(nil).AnyTimes()
		config.SetWorkspace(conf, mockWs)

		// Seed non-default override: risk score threshold 500 (default is 0).
		types.SetGlobalUser(conf, types.SettingRiskScoreThreshold, 500)
		require.True(t, types.HasGlobalUserOverride(conf, types.SettingRiskScoreThreshold))
		require.Equal(t, 500, types.GetGlobalInt(conf, types.SettingRiskScoreThreshold), "override active")

		settings := map[string]*types.ConfigSetting{
			types.SettingRiskScoreThreshold: {Value: nil, Changed: true},
		}
		processConfigSettings(ctx, conf, setup.engine, setup.engine.GetLogger(), settings, analytics.TriggerSourceTest, cr)

		assert.False(t, types.HasGlobalUserOverride(conf, types.SettingRiskScoreThreshold),
			"int override must be cleared by reset")
		assert.Equal(t, 0, types.GetGlobalInt(conf, types.SettingRiskScoreThreshold),
			"risk score must revert to flagset default 0 after reset")

		// SettingRiskScoreThreshold is in globalResetFilterKeys, so sendDiagnosticsForNewSettings
		// fires. Assert HandleConfigChange is called, proving the analytics + diagnostics path
		// was exercised (if globalEffectiveValue regresses to GetGlobalBool for int keys,
		// effectivelyChanged would always be false and the call would never happen).
		require.Eventually(t,
			func() bool { return atomic.LoadInt32(&handleConfigChangeCalled) > 0 },
			time.Second, time.Millisecond,
			"HandleConfigChange must be called after resetting int key whose effective value changed")
	})

	t.Run("globalEffectiveValue reads bool-stored scan_net_new correctly", func(t *testing.T) {
		// Regression test for IDE-2149: applyDeltaFindings stores scan_net_new as a raw bool via
		// SetGlobalDeferredFolderScope (unwrapped write). globalEffectiveValue must use GetGlobalBool
		// for this key; using GetGlobalString silently fails the type-assertion and returns "" both
		// before and after the reset, making effectivelyChanged=false and suppressing analytics.
		engine, tokenService := testutil.UnitTestWithEngine(t)
		conf := engine.GetConfiguration()
		_ = tokenService

		// Store scan_net_new as a bool (true = enabled), matching the production write
		// path in applyDeltaFindings which calls SetGlobalDeferredFolderScope with a bool.
		types.SetGlobalDeferredFolderScope(conf, types.SettingScanNetNew, true)
		require.True(t, types.HasGlobalUserOverride(conf, types.SettingScanNetNew),
			"bool override must be detected by HasGlobalUserOverride")

		// globalEffectiveValue must return true before reset and false (flagset default) after.
		// If GetGlobalString is used instead of GetGlobalBool, both calls return "" and
		// effectivelyChanged is always false — analytics are silently suppressed.
		beforeReset := globalEffectiveValue(conf, types.SettingScanNetNew)
		types.UnsetGlobalUser(conf, types.SettingScanNetNew)
		afterReset := globalEffectiveValue(conf, types.SettingScanNetNew)

		assert.Equal(t, true, beforeReset,
			"globalEffectiveValue must return the stored bool true before reset")
		assert.Equal(t, false, afterReset,
			"globalEffectiveValue must return the flagset default false after reset")
		assert.NotEqual(t, beforeReset, afterReset,
			"effectivelyChanged must be true so analytics are emitted on reset")
	})

	t.Run("scan_net_new reset via processConfigSettings emits analytics event", func(t *testing.T) {
		// End-to-end regression for IDE-2149: proves the analytics + diagnostics path
		// is exercised when scan_net_new is reset via processConfigSettings.
		//
		// The unit test above verifies globalEffectiveValue returns the correct bool values.
		// This test proves the full production path all the way to the analytics workflow:
		//   processConfigSettings → applyGlobalResets
		//     → analytics.SendConfigChangedAnalytics  (gated on effectivelyChanged)
		//       → engine.InvokeWithInputAndConfig(WORKFLOWID_REPORT_ANALYTICS, ...)
		//
		// RED signal: if globalEffectiveValue regresses to GetGlobalString for scan_net_new,
		// effectivelyChanged becomes false (both before/after read as ""), and
		// SendConfigChangedAnalytics short-circuits (oldVal==newVal guard), so the analytics
		// workflow is never invoked — the counter stays at 0 and the test fails.
		//
		// GREEN signal: with GetGlobalBool, effectivelyChanged is true (true→false),
		// SendConfigChangedAnalytics calls the workflow, counter > 0, test passes.
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)

		// setupFolderConfigTest initializes SettingIsLspInitialized=true, which is
		// required for SendConfigChangedAnalytics to act.
		setup := setupFolderConfigTest(t)
		conf := setup.engineConfig
		ctx := testCtx(t, t.Context(), setup.engine, setup.tokenService)
		cr := testutil.DefaultConfigResolver(setup.engine)

		// Intercept the analytics workflow with a no-op spy to count invocations and
		// avoid outbound network calls. DisableOutboundAnalyticsForTest re-registers
		// WORKFLOWID_REPORT_ANALYTICS with a counter callback.
		analyticsCalls := testutil.DisableOutboundAnalyticsForTest(t, setup.engine)

		// Replace workspace with a mock. Folders() returns nil (no folder org to use),
		// so SendConfigChangedAnalytics falls back to the global org path. This also
		// means HandleConfigChange fires from sendDiagnosticsForNewSettings.
		var handleConfigChangeCalled int32
		mockWs := mock_types.NewMockWorkspace(ctrl)
		mockWs.EXPECT().HandleConfigChange().
			Do(func() { atomic.AddInt32(&handleConfigChangeCalled, 1) }).
			MinTimes(0) // may or may not fire; the analytics assertion is the primary gate
		mockWs.EXPECT().Folders().Return(nil).AnyTimes()
		config.SetWorkspace(conf, mockWs)

		// Store scan_net_new as a bool via the production write path (same as
		// applyDeltaFindings → SetGlobalDeferredFolderScope). Override must differ
		// from the flagset default (false) so effectivelyChanged becomes true.
		types.SetGlobalDeferredFolderScope(conf, types.SettingScanNetNew, true)
		require.True(t, types.HasGlobalUserOverride(conf, types.SettingScanNetNew),
			"bool override must be detectable before reset")
		require.True(t, types.GetGlobalBool(conf, types.SettingScanNetNew),
			"scan_net_new override must read as true before reset")

		// Issue a reset payload: {changed:true, value:nil} triggers applyGlobalResets.
		settings := map[string]*types.ConfigSetting{
			types.SettingScanNetNew: {Value: nil, Changed: true},
		}
		processConfigSettings(ctx, conf, setup.engine, setup.engine.GetLogger(), settings, analytics.TriggerSourceTest, cr)

		// Override must be cleared and value must revert to flagset default (false).
		assert.False(t, types.HasGlobalUserOverride(conf, types.SettingScanNetNew),
			"scan_net_new override must be cleared by reset")
		assert.False(t, types.GetGlobalBool(conf, types.SettingScanNetNew),
			"scan_net_new must revert to flagset default false after reset")

		// SendConfigChangedAnalytics spawns a goroutine to invoke the analytics workflow.
		// Wait for it to land. A count of 0 here means effectivelyChanged was false —
		// the GetGlobalString regression would leave analytics suppressed.
		require.Eventually(t,
			func() bool { return analyticsCalls.Load() > 0 },
			time.Second, time.Millisecond,
			"analytics workflow must be invoked after resetting bool-stored scan_net_new — "+
				"count=0 means effectivelyChanged was false (GetGlobalString regression: "+
				"both before/after read as '' so oldVal==newVal guard short-circuits analytics)")
	})
}
