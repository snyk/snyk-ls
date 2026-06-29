/*
 * © 2026 Snyk Limited
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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2/server"
	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	shellenv "github.com/snyk/snyk-ls/internal"
	"github.com/snyk/snyk-ls/internal/notification"
	storage2 "github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_E2E_AuthenticationLoginAndLogoutFlow(t *testing.T) {
	engine, tokenService := newAuthFlowE2EEngine(t, "http://127.0.0.1", filepath.Join(t.TempDir(), "ls-config.json"))
	engine.GetConfiguration().Set(configuration.INTEGRATION_ENVIRONMENT, "IDE-1900-login-logout")
	loc, recorder, authService := startE2ELocalServer(t, engine, tokenService, nil)

	token := oauthTokenJSONForServerE2E(t, "login-access", "login-refresh", time.Now().Add(time.Hour))
	authService.SetProvider(&authentication.FakeAuthenticationProvider{
		Engine:        engine,
		TokenToReturn: token,
	})

	require.NoError(t, initializeLSPClientOnly(t, loc, types.InitializeParams{}))
	recorder.ClearNotifications()

	loginResponse, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command: types.LoginCommand,
	})
	require.NoError(t, err)
	var loginToken string
	require.NoError(t, loginResponse.UnmarshalResult(&loginToken))
	assert.Equal(t, token, loginToken)

	require.NoError(t, initializedLSPClient(t, loc))
	authAfterLogin := requireAuthNotification(t, recorder, token)
	assert.Equal(t, token, authAfterLogin.Token)
	assert.Equal(t, token, config.GetToken(engine.GetConfiguration()))

	recorder.ClearNotifications()
	_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command: types.LogoutCommand,
	})
	require.NoError(t, err)

	authAfterLogout := requireAuthNotification(t, recorder, "")
	assert.Empty(t, authAfterLogout.Token)
	assert.Empty(t, config.GetToken(engine.GetConfiguration()))
}

func Test_E2E_AuthenticationMethodAndTokenConfigurationFlow(t *testing.T) {
	engine, tokenService := newAuthFlowE2EEngine(t, "http://127.0.0.1", filepath.Join(t.TempDir(), "ls-config.json"))
	engine.GetConfiguration().Set(configuration.INTEGRATION_ENVIRONMENT, "IDE-1900-auth-method")
	loc, _, _ := startE2ELocalServer(t, engine, tokenService, nil)

	require.NoError(t, initializeLSPClientOnly(t, loc, types.InitializeParams{}))

	apiToken := "11111111-1111-4111-8111-111111111111"
	_, err := loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingAuthenticationMethod: {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingToken:                {Value: apiToken, Changed: true},
			},
		},
	})
	require.NoError(t, err)

	assert.Equal(t, types.TokenAuthentication, config.GetAuthenticationMethodFromConfig(engine.GetConfiguration()))
	assert.Equal(t, apiToken, config.GetToken(engine.GetConfiguration()))
}

func Test_E2E_AuthenticationMethodChangeClearsIncompatibleToken(t *testing.T) {
	engine, tokenService := newAuthFlowE2EEngine(t, "http://127.0.0.1", filepath.Join(t.TempDir(), "ls-config.json"))
	engine.GetConfiguration().Set(configuration.INTEGRATION_ENVIRONMENT, "IDE-1900-auth-method-clears-token")
	loc, recorder, _ := startE2ELocalServer(t, engine, tokenService, nil)

	require.NoError(t, initializeLSPClientOnly(t, loc, types.InitializeParams{}))
	require.NoError(t, initializedLSPClient(t, loc))

	apiToken := "22222222-2222-4222-8222-222222222222"
	_, err := loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingAuthenticationMethod: {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingToken:                {Value: apiToken, Changed: true},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, apiToken, config.GetToken(engine.GetConfiguration()))

	recorder.ClearNotifications()
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingAuthenticationMethod: {Value: string(types.OAuthAuthentication), Changed: true},
			},
		},
	})
	require.NoError(t, err)

	authAfterMethodChange := requireAuthNotification(t, recorder, "")
	assert.Empty(t, authAfterMethodChange.Token)
	assert.Empty(t, config.GetToken(engine.GetConfiguration()))
	assert.Equal(t, types.OAuthAuthentication, config.GetAuthenticationMethodFromConfig(engine.GetConfiguration()))
}

func Test_E2E_EndpointChangeAfterInitializationClearsToken(t *testing.T) {
	engine, tokenService := newAuthFlowE2EEngine(t, "http://127.0.0.1", filepath.Join(t.TempDir(), "ls-config.json"))
	engine.GetConfiguration().Set(configuration.INTEGRATION_ENVIRONMENT, "IDE-1900-endpoint-clears-token")
	loc, recorder, _ := startE2ELocalServer(t, engine, tokenService, nil)

	require.NoError(t, initializeLSPClientOnly(t, loc, types.InitializeParams{}))
	require.NoError(t, initializedLSPClient(t, loc))

	apiToken := "33333333-3333-4333-8333-333333333333"
	_, err := loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingAuthenticationMethod: {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingToken:                {Value: apiToken, Changed: true},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, apiToken, config.GetToken(engine.GetConfiguration()))

	recorder.ClearNotifications()
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingApiEndpoint: {Value: "https://api.changed.example", Changed: true},
			},
		},
	})
	require.NoError(t, err)

	authAfterEndpointChange := requireAuthNotification(t, recorder, "")
	assert.Empty(t, authAfterEndpointChange.Token)
	assert.Empty(t, config.GetToken(engine.GetConfiguration()))
	assert.Equal(t, "https://api.changed.example", types.GetGlobalString(engine.GetConfiguration(), types.SettingApiEndpoint))
}

func Test_E2E_IsAuthenticatedFalseSkipsActiveUserLookup(t *testing.T) {
	engine, tokenService := newAuthFlowE2EEngine(t, "http://127.0.0.1", filepath.Join(t.TempDir(), "ls-config.json"))
	engine.GetConfiguration().Set(configuration.INTEGRATION_ENVIRONMENT, "IDE-1900-is-authenticated")
	types.SetGlobalUser(engine.GetConfiguration(), types.SettingAuthenticationMethod, string(types.FakeAuthentication))
	loc, _, authService := startE2ELocalServer(t, engine, tokenService, nil)

	fakeProvider := &authentication.FakeAuthenticationProvider{
		Engine:          engine,
		IsAuthenticated: false,
		Method:          types.FakeAuthentication,
	}
	authService.SetProvider(fakeProvider)
	tokenService.SetToken(engine.GetConfiguration(), "fake-token-for-auth-check")

	require.NoError(t, initializeLSPClientOnly(t, loc, types.InitializeParams{}))
	response, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command: types.GetActiveUserCommand,
	})
	require.NoError(t, err)

	assert.Equal(t, "null", response.ResultString())
	assert.Equal(t, int32(1), atomic.LoadInt32(&fakeProvider.AuthCallCount), "getActiveUser must exercise IsAuthenticated through the LSP command")
}

func Test_E2E_OAuthRestartRefreshesPersistedTokenOnce(t *testing.T) {
	ideName := "IDE-1900-e2e-" + filepath.Base(t.TempDir())
	apiURL := "http://127.0.0.1"
	configFile := filepath.Join(t.TempDir(), "ls-config.json")
	initialExpiry := time.Now().Add(time.Second)
	initialToken := oauthTokenJSONForServerE2E(t, "access-before-restart", "refresh-before-restart", initialExpiry)

	engine1, tokenService1 := newAuthFlowE2EEngine(t, apiURL, configFile)
	engine1.GetConfiguration().Set(configuration.INTEGRATION_ENVIRONMENT, ideName)
	loc1, recorder1, authService1 := startE2ELocalServer(t, engine1, tokenService1, nil)

	authService1.SetProvider(&authentication.FakeAuthenticationProvider{
		Engine:        engine1,
		TokenToReturn: initialToken,
	})

	require.NoError(t, initializeLSPClientOnly(t, loc1, types.InitializeParams{}))
	recorder1.ClearNotifications()

	loginResponse, err := loc1.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command: types.LoginCommand,
	})
	require.NoError(t, err)
	var loginToken string
	require.NoError(t, loginResponse.UnmarshalResult(&loginToken))
	assert.Equal(t, initialToken, loginToken)

	require.NoError(t, initializedLSPClient(t, loc1))
	authFromLogin := requireAuthNotification(t, recorder1, initialToken)
	assert.Equal(t, initialToken, authFromLogin.Token)

	require.NoError(t, shutdownLSPClient(t, loc1))
	persistOAuthTokenForRestart(t, configFile, initialToken)

	if wait := time.Until(initialExpiry.Add(100 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}

	refreshedToken := oauthTokenJSONForServerE2E(t, "access-after-refresh", "refresh-after-refresh", time.Now().Add(time.Hour))
	refreshRecorder := &oauthRefreshRecorder{
		t:                    t,
		expectedRefreshToken: "refresh-before-restart",
		refreshedToken:       refreshedToken,
	}

	engine2, tokenService2 := newAuthFlowE2EEngine(t, apiURL, configFile)
	conf2 := engine2.GetConfiguration()
	conf2.Set(configuration.INTEGRATION_ENVIRONMENT, ideName)
	types.SetGlobalUser(conf2, types.SettingAuthenticationMethod, string(types.OAuthAuthentication))
	tokenService2.SetToken(conf2, initialToken)

	var startupAuth *startupAuthRequestLdxSyncService
	loc2, recorder2, authService2 := startE2ELocalServer(t, engine2, tokenService2, func(deps di.Dependencies) di.Dependencies {
		authProvider := authentication.NewOAuthProvider(
			engine2,
			refreshRecorder.refreshToken,
			nil,
			nil,
		)
		deps.AuthenticationService.SetProvider(authProvider)
		startupAuth = &startupAuthRequestLdxSyncService{
			t:           t,
			authService: deps.AuthenticationService,
		}
		deps.LdxSyncService = startupAuth
		return deps
	})

	require.NoError(t, initializeLSPClientOnly(t, loc2, types.InitializeParams{
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingAuthenticationMethod: {Value: string(types.OAuthAuthentication), Changed: true},
				types.SettingToken:                {Value: initialToken, Changed: true},
			},
		},
	}))

	authService2.SetProvider(&authentication.FakeAuthenticationProvider{
		Engine:          engine2,
		IsAuthenticated: true,
		Method:          types.OAuthAuthentication,
	})
	require.NoError(t, initializedLSPClient(t, loc2))

	authAfterRestart := requireAuthNotification(t, recorder2, refreshedToken)
	assert.Equal(t, refreshedToken, authAfterRestart.Token)
	for _, notification := range recorder2.FindNotificationsByMethod("$/snyk.hasAuthenticated") {
		var authParams types.AuthenticationParams
		require.NoError(t, notification.UnmarshalParams(&authParams))
		assert.NotEqual(t, initialToken, authParams.Token, "stale restart token must not be sent back to the IDE")
		assert.NotEmpty(t, authParams.Token, "restart refresh must not produce a logout notification")
	}
	assert.Equal(t, refreshedToken, config.GetToken(conf2))
	assert.Equal(t, int32(1), refreshRecorder.Count(), "expired restart token should be refreshed exactly once")
	assert.Equal(t, []string{"refresh-before-restart"}, refreshRecorder.RefreshTokens(), "refresh must use the IDE's last persisted token")
	assert.Equal(t, []string{"Bearer access-after-refresh"}, startupAuth.AuthorizationHeaders())
	assert.NotContains(t, startupAuth.AuthorizationHeaders(), "Bearer access-before-restart", "stale access token must not be used for authenticated startup calls")
}

type oauthRefreshRecorder struct {
	t                    *testing.T
	expectedRefreshToken string
	refreshedToken       string
	mu                   sync.Mutex
	refreshTokens        []string
}

func (r *oauthRefreshRecorder) refreshToken(_ context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshTokens = append(r.refreshTokens, token.RefreshToken)
	require.Equal(r.t, r.expectedRefreshToken, token.RefreshToken)

	var refreshed oauth2.Token
	require.NoError(r.t, json.Unmarshal([]byte(r.refreshedToken), &refreshed))
	return &refreshed, nil
}

func (r *oauthRefreshRecorder) Count() int32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int32(len(r.refreshTokens))
}

func (r *oauthRefreshRecorder) RefreshTokens() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.refreshTokens...)
}

type startupAuthRequestLdxSyncService struct {
	t           *testing.T
	authService authentication.AuthenticationService
	mu          sync.Mutex
	headers     []string
}

func (s *startupAuthRequestLdxSyncService) RefreshConfigFromLdxSync(ctx context.Context, _ configuration.Configuration, _ workflow.Engine, _ *zerolog.Logger, _ []types.Folder, _ notification.Notifier) {
	provider, ok := s.authService.Provider().(*authentication.OAuth2Provider)
	require.True(s.t, ok)

	req := httptest.NewRequest(http.MethodGet, "https://api.snyk.io/rest/self", nil).WithContext(ctx)
	require.NoError(s.t, provider.Authenticator().AddAuthenticationHeader(req))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers = append(s.headers, req.Header.Get("Authorization"))
}

func (s *startupAuthRequestLdxSyncService) AuthorizationHeaders() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.headers...)
}

func startE2ELocalServer(
	t *testing.T,
	engine workflow.Engine,
	tokenService *config.TokenServiceImpl,
	configureDeps func(di.Dependencies) di.Dependencies,
) (server.Local, *testsupport.JsonRPCRecorder, authentication.AuthenticationService) {
	t.Helper()

	testutil.DisableOutboundAnalyticsForTest(t, engine)
	deps := di.TestInit(t, engine, tokenService, nil)
	if configureDeps != nil {
		deps = configureDeps(deps)
	}
	command.SetService(command.NewService(
		engine,
		engine.GetLogger(),
		deps.AuthenticationService,
		deps.FeatureFlagService,
		deps.Notifier,
		deps.LearnService,
		nil,
		nil,
		nil,
		deps.LdxSyncService,
		deps.ConfigResolver,
		nil,
		nil,
	))
	recorder := &testsupport.JsonRPCRecorder{}
	loc := startServer(engine, tokenService, nil, recorder, deps)
	cleanupChannels()

	t.Cleanup(func() {
		_ = shutdownLSPClient(t, loc)
		cleanupChannels()
		recorder.ClearCallbacks()
		recorder.ClearNotifications()
	})

	return loc, recorder, deps.AuthenticationService
}

func initializeLSPClientOnly(t *testing.T, loc server.Local, params types.InitializeParams) error {
	t.Helper()

	_, err := loc.Client.Call(t.Context(), "initialize", params)
	return err
}

func initializedLSPClient(t *testing.T, loc server.Local) error {
	t.Helper()

	_, err := loc.Client.Call(t.Context(), "initialized", types.InitializedParams{})
	return err
}

func shutdownLSPClient(t *testing.T, loc server.Local) error {
	t.Helper()

	_, _ = loc.Client.Call(context.Background(), "shutdown", nil)
	return loc.Close()
}

func requireAuthNotification(t *testing.T, recorder *testsupport.JsonRPCRecorder, expectedToken string) types.AuthenticationParams {
	t.Helper()

	var matched types.AuthenticationParams
	require.Eventually(t, func() bool {
		for _, notification := range recorder.FindNotificationsByMethod("$/snyk.hasAuthenticated") {
			var authParams types.AuthenticationParams
			if err := notification.UnmarshalParams(&authParams); err != nil {
				continue
			}
			if authParams.Token == expectedToken {
				matched = authParams
				return true
			}
		}
		return false
	}, 5*time.Second, 50*time.Millisecond)
	return matched
}

func oauthTokenJSONForServerE2E(t *testing.T, accessToken string, refreshToken string, expiry time.Time) string {
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

func persistOAuthTokenForRestart(t *testing.T, configFile string, token string) {
	t.Helper()

	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(configFile))
	require.NoError(t, err)
	require.NoError(t, storageWithCallbacks.Set(auth.CONFIG_KEY_OAUTH_TOKEN, token))
}

var _ command.LdxSyncService = (*startupAuthRequestLdxSyncService)(nil)

func newAuthFlowE2EEngine(t *testing.T, apiURL string, configFile string) (workflow.Engine, *config.TokenServiceImpl) {
	t.Helper()
	t.Setenv(shellenv.DisableShellEnvLoadingEnvVar, "1")

	conf := configuration.NewWithOpts()
	conf.Set(configuration.API_URL, apiURL)
	conf.Set(configuration.ORGANIZATION, "00000000-0000-0000-0000-000000000000")
	conf.Set(configuration.ORGANIZATION_SLUG, "e2e-org")
	conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)

	engine := app.CreateAppEngineWithOptions(app.WithConfiguration(conf))
	require.NoError(t, config.InitWorkflows(engine))
	require.NoError(t, engine.Init())

	engine, tokenService := config.InitEngine(engine)
	conf = engine.GetConfiguration()
	types.SetGlobalSystemDefault(conf, types.SettingConfigFile, configFile)
	conf.Set(types.SettingConfigFileLegacy, configFile)
	require.NoError(t, os.MkdirAll(filepath.Dir(configFile), 0o755))
	require.NoError(t, os.WriteFile(configFile, []byte("{}"), 0o600))
	return engine, tokenService
}
