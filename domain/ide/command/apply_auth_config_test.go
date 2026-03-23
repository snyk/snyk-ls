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

	changed := ApplyEndpointChange(t.Context(), conf, authService, "https://api.custom.io")

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

	changed := ApplyEndpointChange(t.Context(), conf, authService, "https://api.custom.io")

	assert.True(t, changed)
	assert.Equal(t, "some-token", config.GetToken(conf), "token must be preserved when LSP is not initialized")
}

func TestApplyEndpointChange_EndpointSame_ReturnsFalse(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ts.SetToken(conf, "some-token")

	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	authService := authentication.NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	defaultEndpoint := conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint))
	changed := ApplyEndpointChange(t.Context(), conf, authService, defaultEndpoint)

	assert.False(t, changed)
	assert.Equal(t, "some-token", config.GetToken(conf), "token must be preserved when endpoint is unchanged")
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
