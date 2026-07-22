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
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	gafConfig "github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestApplyAuthMethodChange_CancelsInFlightLoginWhenMethodChanges(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))

	provider := authentication.NewBlockingFakeAuthProvider()
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	// Start a login that blocks until its context is canceled, simulating a stuck auth.
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = authService.Authenticate(context.Background())
	}()

	select {
	case <-provider.Started:
	case <-time.After(time.Second):
		t.Fatal("Authenticate did not start")
	}

	// Switching the auth method must cancel the in-flight login for the previous method. Run it in a
	// goroutine so a regression (ConfigureProviders deadlocking behind the stuck login's mutex) is
	// reported by this explicit timeout rather than the global test timeout.
	acDone := make(chan bool, 1)
	go func() {
		acDone <- ApplyAuthMethodChange(conf, authService, engine.GetLogger(), types.TokenAuthentication)
	}()

	var changed bool
	select {
	case changed = <-acDone:
	case <-time.After(2 * time.Second):
		t.Fatal("ApplyAuthMethodChange deadlocked — it must cancel the in-flight login before ConfigureProviders acquires the auth mutex")
	}
	assert.True(t, changed)

	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("ApplyAuthMethodChange did not cancel the in-flight login")
	}
}

func TestApplyEndpointChange_EndpointChanges_LSPInitialized_LogsOutAndClearsWorkspace(t *testing.T) {
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

	changed := ApplyEndpointChange(t.Context(), conf, authService, engine.GetLogger(), "https://api.custom.io")

	assert.True(t, changed)
	assert.Empty(t, config.GetToken(conf), "Logout must clear the token when endpoint changes and LSP is initialized")
}

func TestApplyEndpointChange_EndpointChanges_LSPNotInitialized_NoLogout(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ts.SetToken(conf, "some-token")
	// LSP not initialized (default from UnitTest)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	changed := ApplyEndpointChange(t.Context(), conf, authService, engine.GetLogger(), "https://api.custom.io")

	assert.True(t, changed)
	assert.Equal(t, "some-token", config.GetToken(conf), "token must be preserved when LSP is not initialized")
}

func TestApplyEndpointChange_EndpointSame_ReturnsFalse(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ts.SetToken(conf, "some-token")

	// Initialize a concrete endpoint so there is a stored value to compare against.
	sameEndpoint := "https://api.custom.io"
	config.UpdateApiEndpointsOnConfig(conf, sameEndpoint)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	changed := ApplyEndpointChange(t.Context(), conf, authService, engine.GetLogger(), sameEndpoint)

	assert.False(t, changed)
	assert.Equal(t, "some-token", config.GetToken(conf), "token must be preserved when endpoint is unchanged")
}

func TestApplyEndpointChange_NilAuthService_LSPNotInitialized_MutationProceeds(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	// LSP not initialized — no logout needed, so nil authService must not block the change.
	changed := ApplyEndpointChange(t.Context(), conf, nil, engine.GetLogger(), "https://api.custom.io")

	assert.True(t, changed)
	assert.Equal(t, "https://api.custom.io", types.GetGlobalString(conf, types.SettingApiEndpoint))
}

func TestApplyEndpointChange_NilAuthService_LSPInitialized_SkipsMutationAndReturnsFalse(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	conf.Set(types.SettingIsLspInitialized, true)
	originalEndpoint := types.GetGlobalString(conf, types.SettingApiEndpoint)

	// When authService is nil and LSP is initialized, the config must NOT be mutated —
	// switching endpoints without logging out would leave credentials pointing at the wrong endpoint.
	changed := ApplyEndpointChange(t.Context(), conf, nil, engine.GetLogger(), "https://api.custom.io")

	assert.False(t, changed)
	assert.Equal(t, originalEndpoint, types.GetGlobalString(conf, types.SettingApiEndpoint), "endpoint must not be mutated when logout cannot be performed")
}

func TestApplyInsecureSetting_SetsInsecureFlag(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	ApplyInsecureSetting(conf, true)
	assert.True(t, conf.GetBool(gafConfig.INSECURE_HTTPS))

	ApplyInsecureSetting(conf, false)
	assert.False(t, conf.GetBool(gafConfig.INSECURE_HTTPS))
}

func TestApplyAuthMethodChange_MethodChanges_EndpointNotChanged_ConfiguresProviders(t *testing.T) {
	// ApplyAuthMethodChange must not call Logout explicitly on method change; ConfigureProviders
	// handles credential validation internally.
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	setMockWorkspace(t, ctrl, conf)

	fakeProvider := &authentication.FakeAuthenticationProvider{Engine: engine}
	authService := authentication.NewAuthenticationService(engine, ts, fakeProvider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	changed := ApplyAuthMethodChange(conf, authService, engine.GetLogger(), types.TokenAuthentication)

	assert.True(t, changed)
	assert.Equal(t, types.TokenAuthentication, config.GetAuthenticationMethodFromConfig(conf))
	assert.False(t, fakeProvider.ClearAuthenticationCalled, "ClearAuthentication on the old provider must not be called directly on auth method change")
}

func TestApplyAuthMethodChange_MethodSame_ReturnsFalse(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	// UnitTest sets FakeAuthentication by default
	ts.SetToken(conf, "some-token")

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	setMockWorkspace(t, ctrl, conf)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	changed := ApplyAuthMethodChange(conf, authService, engine.GetLogger(), types.FakeAuthentication)

	assert.False(t, changed)
	assert.Equal(t, types.FakeAuthentication, config.GetAuthenticationMethodFromConfig(conf))
	assert.Equal(t, "some-token", config.GetToken(conf), "token must be preserved when auth method is unchanged")
}

// TestApplyAuthMethodChange_NilAuthService removed: authService is now guaranteed
// non-nil by withContext.validateMandatoryDeps before any handler runs.

func TestApplyAuthMethodChange_EmptyMethod_NoEffect(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ts.SetToken(conf, "some-token")
	originalMethod := config.GetAuthenticationMethodFromConfig(conf)

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	changed := ApplyAuthMethodChange(conf, authService, engine.GetLogger(), types.EmptyAuthenticationMethod)

	assert.False(t, changed)
	assert.Equal(t, originalMethod, config.GetAuthenticationMethodFromConfig(conf), "method must be unchanged for empty input")
	assert.Equal(t, "some-token", config.GetToken(conf), "token must be preserved for empty method input")
}
