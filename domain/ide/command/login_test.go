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

package command

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

// setMockWorkspace creates a mock workspace with no folders and attaches it to the config.
func setMockWorkspace(t *testing.T, ctrl *gomock.Controller, conf configuration.Configuration) {
	t.Helper()
	mockWs := mock_types.NewMockWorkspace(ctrl)
	mockWs.EXPECT().Folders().Return([]types.Folder{}).AnyTimes()
	config.SetWorkspace(conf, mockWs)
}

func TestLoginCommand_Execute_NoArgs_AuthenticatesNormally(t *testing.T) {
	// Verifies that Execute completes the auth flow (token returned, LDX sync triggered)
	// when no arguments are provided. Auth behavior is delegated to FakeCliAuthenticationProvider.
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	setMockWorkspace(t, ctrl, conf)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)
	mockLdxSync.EXPECT().RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	cmd := loginCommand{
		command:            types.CommandData{CommandId: types.LoginCommand},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		engine:             engine,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestLoginCommand_Execute_ThreeArgs_AppliesConfigBeforeAuth(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	setMockWorkspace(t, ctrl, conf)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)
	mockLdxSync.EXPECT().RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			// args: authMethod=fake, endpoint=https://api.snyk.io, insecure=false
			Arguments: []any{"fake", "https://api.snyk.io", false},
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		engine:             engine,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, types.FakeAuthentication, config.GetAuthenticationMethodFromConfig(conf))
}

func TestLoginCommand_Execute_ThreeArgs_InsecureAsString(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	setMockWorkspace(t, ctrl, conf)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)
	mockLdxSync.EXPECT().RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			// insecure is a string "true" — IDEs may serialize booleans as strings over JSON
			Arguments: []any{"fake", "https://api.snyk.io", "true"},
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		engine:             engine,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestLoginCommand_Execute_InvalidAuthMethodArg_ReturnsError(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			// invalid: authMethod is an int instead of a string
			Arguments: []any{123, "https://api.snyk.io", false},
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		engine:             engine,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestApplyAuthConfig_EndpointChange_LogsOutAndClearsWorkspace(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	conf.Set(types.SettingIsLspInitialized, true)
	ts.SetToken(conf, "some-token")

	mockWs := mock_types.NewMockWorkspace(ctrl)
	mockWs.EXPECT().Clear().Times(1)
	mockWs.EXPECT().Folders().Return([]types.Folder{}).AnyTimes()
	config.SetWorkspace(conf, mockWs)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{"fake", "https://api.custom.io", false},
		},
		authService: authService,
		notifier:    notification.NewMockNotifier(),
		engine:      engine,
	}

	err := cmd.applyAuthConfig(t.Context(), conf, engine.GetLogger())

	require.NoError(t, err)
	assert.Empty(t, config.GetToken(conf), "endpoint change with LSP initialized must trigger logout")
}

func TestApplyAuthConfig_ClearsTokenWhenAuthMethodChanges(t *testing.T) {
	// OAuth JSON tokens don't match TokenAuthentication, so without pre-clearing, configureProviders
	// would detect a mismatch and call logout() → CliAuthenticationProvider.ClearAuthentication() which
	// spawns a slow CLI subprocess. With the fix, Logout is called before setting the new method,
	// which clears the token before ConfigureProviders runs.
	// The test uses FakeAuthentication (matching FakeCliAuthenticationProvider) as the starting method
	// so that configureProviders inside Logout does not attempt to create an OAuth provider.
	oAuthToken := "{\"access_token\":\"eyJhbGciOiJSUzI1NiJ9.e30.sig\",\"token_type\":\"bearer\"," +
		"\"refresh_token\":\"snyk_rt_abc123\",\"expiry\":\"1970-01-01T00:00:00Z\"}"

	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	// FakeAuthentication is the default from UnitTest; keep it consistent with FakeCliAuthenticationProvider.
	ts.SetToken(conf, oAuthToken)

	setMockWorkspace(t, ctrl, conf)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{"token", "https://api.snyk.io", false},
		},
		authService: authService,
		notifier:    notification.NewMockNotifier(),
		engine:      engine,
	}

	err := cmd.applyAuthConfig(t.Context(), conf, engine.GetLogger())

	require.NoError(t, err)
	assert.Empty(t, config.GetToken(conf), "token must be cleared when auth method changes")
}

func TestApplyAuthConfig_PreservesTokenWhenAuthMethodUnchanged(t *testing.T) {
	// UUID matches TokenAuthentication, so no mismatch is detected in configureProviders.
	// When the same method is re-sent, the token should not be cleared.
	apiToken := "e24850f4-c252-4813-b37e-21825873038e"

	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	conf.Set(types.SettingAuthenticationMethod, string(types.TokenAuthentication))
	ts.SetToken(conf, apiToken)

	setMockWorkspace(t, ctrl, conf)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{"token", "https://api.snyk.io", false},
		},
		authService: authService,
		notifier:    notification.NewMockNotifier(),
		engine:      engine,
	}

	err := cmd.applyAuthConfig(t.Context(), conf, engine.GetLogger())

	require.NoError(t, err)
	assert.Equal(t, apiToken, config.GetToken(conf), "token must be preserved when auth method is unchanged")
}

func TestLoginCommand_Execute_NilInsecureArg_AuthenticatesNormally(t *testing.T) {
	// IDEs that omit the insecure field serialize it as JSON null, which decodes to nil.
	// ParseBoolArg must treat nil as false rather than returning an error that aborts auth.
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	setMockWorkspace(t, ctrl, conf)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)
	mockLdxSync.EXPECT().RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{"fake", "https://api.snyk.io", nil}, // nil from JSON null
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		engine:             engine,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestLoginCommand_Execute_InvalidArgCount_ReturnsError(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{"oauth"}, // invalid: 1 arg, must be 0 or 3
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		engine:             engine,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestLoginCommand_Execute_InvalidInsecureArg_ReturnsError(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{"oauth", "https://api.snyk.io", 42}, // invalid: int instead of bool/string
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		engine:             engine,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.Error(t, err)
	assert.Nil(t, result)
}
