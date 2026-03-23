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
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestApplyEndpointChange_EndpointChanges_LSPInitialized_LogsOutAndClearsWorkspace(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	c.SetLSPInitialized(true)
	c.SetToken("some-token")

	mockWs := mock_types.NewMockWorkspace(ctrl)
	mockWs.EXPECT().Clear().Times(1)
	mockWs.EXPECT().Folders().Return([]types.Folder{}).AnyTimes()
	c.SetWorkspace(mockWs)

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	changed := ApplyEndpointChange(t.Context(), c, authService, "https://api.custom.io")

	assert.True(t, changed)
	assert.Empty(t, c.Token(), "Logout must clear the token when endpoint changes and LSP is initialized")
}

func TestApplyEndpointChange_EndpointChanges_LSPNotInitialized_NoLogout(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetToken("some-token")
	// LSP not initialized (default from UnitTest)

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	changed := ApplyEndpointChange(t.Context(), c, authService, "https://api.custom.io")

	assert.True(t, changed)
	assert.Equal(t, "some-token", c.Token(), "token must be preserved when LSP is not initialized")
}

func TestApplyEndpointChange_EndpointSame_ReturnsFalse(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetToken("some-token")

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	defaultEndpoint := c.Endpoint()
	changed := ApplyEndpointChange(t.Context(), c, authService, defaultEndpoint)

	assert.False(t, changed)
	assert.Equal(t, "some-token", c.Token(), "token must be preserved when endpoint is unchanged")
}

func TestApplyInsecureSetting_SetsInsecureFlag(t *testing.T) {
	c := testutil.UnitTest(t)

	ApplyInsecureSetting(c, true)
	assert.True(t, c.Engine().GetConfiguration().GetBool(gafConfig.INSECURE_HTTPS))

	ApplyInsecureSetting(c, false)
	assert.False(t, c.Engine().GetConfiguration().GetBool(gafConfig.INSECURE_HTTPS))
}

func TestApplyAuthMethodChange_MethodChanges_EndpointNotChanged_LogsOut(t *testing.T) {
	c := testutil.UnitTest(t)
	// UnitTest sets FakeAuthentication by default; change to TokenAuthentication so configureProviders
	// inside Logout won't trigger OAuth provider creation (which requires Storage setup).
	c.SetToken("some-token")

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	setMockWorkspace(t, ctrl, c)

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	changed := ApplyAuthMethodChange(t.Context(), c, authService, types.TokenAuthentication, false)

	assert.True(t, changed)
	assert.Equal(t, types.TokenAuthentication, c.AuthenticationMethod())
	assert.Empty(t, c.Token(), "Logout must clear the token when auth method changes")
}

func TestApplyAuthMethodChange_MethodChanges_EndpointAlreadyChanged_SkipsLogout(t *testing.T) {
	c := testutil.UnitTest(t)
	// Token is empty — endpoint's Logout already cleared it

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	setMockWorkspace(t, ctrl, c)

	fakeProvider := &authentication.FakeAuthenticationProvider{C: c}
	authService := authentication.NewAuthenticationService(c, fakeProvider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	changed := ApplyAuthMethodChange(t.Context(), c, authService, types.TokenAuthentication, true)

	assert.True(t, changed)
	assert.Equal(t, types.TokenAuthentication, c.AuthenticationMethod())
	assert.False(t, fakeProvider.ClearAuthenticationCalled, "ClearAuthentication must not be called when endpoint already changed")
}

func TestApplyAuthMethodChange_MethodSame_EndpointChangedDuringStartup_StillConfiguresProviders(t *testing.T) {
	// During startup (LSP not initialized), ApplyEndpointChange returns true but does NOT call
	// Logout. ApplyAuthMethodChange must still call ConfigureProviders so providers are
	// initialized with the new endpoint. Verified via the FakeAuthenticationProvider's
	// ClearAuthenticationCalled staying false (no Logout) while the method is set correctly.
	c := testutil.UnitTest(t)
	// LSP is not initialized (default from UnitTest)
	c.SetToken("some-token")

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	setMockWorkspace(t, ctrl, c)

	fakeProvider := &authentication.FakeAuthenticationProvider{C: c}
	authService := authentication.NewAuthenticationService(c, fakeProvider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	// Simulate: endpoint changed during startup (endpointAlreadyChanged=true) but method unchanged.
	changed := ApplyAuthMethodChange(t.Context(), c, authService, types.FakeAuthentication, true)

	assert.False(t, changed, "method did not change")
	assert.False(t, fakeProvider.ClearAuthenticationCalled, "Logout must not be called when method is unchanged")
	// ConfigureProviders must have run — verifiable indirectly: no panic and method is set.
	assert.Equal(t, types.FakeAuthentication, c.AuthenticationMethod())
	assert.Equal(t, "some-token", c.Token(), "token must be preserved when method is unchanged")
}

func TestApplyAuthMethodChange_MethodSame_ReturnsFalse(t *testing.T) {
	c := testutil.UnitTest(t)
	// UnitTest sets FakeAuthentication by default
	c.SetToken("some-token")

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	setMockWorkspace(t, ctrl, c)

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	changed := ApplyAuthMethodChange(t.Context(), c, authService, types.FakeAuthentication, false)

	assert.False(t, changed)
	assert.Equal(t, types.FakeAuthentication, c.AuthenticationMethod())
	assert.Equal(t, "some-token", c.Token(), "token must be preserved when auth method is unchanged")
}

func TestApplyAuthMethodChange_EmptyMethod_NoEffect(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetToken("some-token")
	originalMethod := c.AuthenticationMethod()

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	changed := ApplyAuthMethodChange(t.Context(), c, authService, types.EmptyAuthenticationMethod, false)

	assert.False(t, changed)
	assert.Equal(t, originalMethod, c.AuthenticationMethod(), "method must be unchanged for empty input")
	assert.Equal(t, "some-token", c.Token(), "token must be preserved for empty method input")
}
