/*
 * © 2023-2026 Snyk Limited
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// setupLoginCmd creates a loginCommand with a shared notifier so that both the auth service and the command
// send to the same mock notifier. This is necessary because UpdateCredentials sends via the auth service's notifier.
func setupLoginCmd(
	t *testing.T,
	c *config.Config,
	provider authentication.AuthenticationProvider,
	args []any,
) (loginCommand, *notification.MockNotifier) {
	t.Helper()
	sharedNotifier := notification.NewMockNotifier()
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), sharedNotifier)
	cmd := loginCommand{
		command:     types.CommandData{CommandId: types.LoginCommand, Arguments: args},
		authService: authService,
		notifier:    sharedNotifier,
		c:           c,
	}
	return cmd, sharedNotifier
}

func TestLoginCommand_Execute_ThreeArgs_AppliesConfigAndSendsNotification(t *testing.T) {
	const endpoint = "https://api.snyk.io"
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	cmd, cmdNotifier := setupLoginCmd(t, c, provider, []any{"fake", endpoint, false})

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.Nil(t, result, "settings page login must return nil")
	assert.Equal(t, 0, cmdNotifier.SendErrorCount(), "no error notification should be sent on success")
	sentMessages := cmdNotifier.SentMessages()
	require.Len(t, sentMessages, 1, "settings page login must send exactly one $/snyk.hasAuthenticated notification")
	authParams, ok := sentMessages[0].(types.AuthenticationParams)
	require.True(t, ok, "notification payload must be AuthenticationParams")
	assert.NotEmpty(t, authParams.Token, "notification must carry a non-empty token")
	// The endpoint is applied to LS config before auth, so c.SnykApi() returns it.
	assert.Equal(t, c.SnykApi(), authParams.ApiUrl, "notification must carry the current API URL")
}

func TestLoginCommand_Execute_ZeroArgs_PersistsTokenAndSendsNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetAuthenticationMethod(types.FakeAuthentication)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	cmd, cmdNotifier := setupLoginCmd(t, c, provider, []any{})

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.Nil(t, result, "panel login must return nil")
	assert.Equal(t, 0, cmdNotifier.SendErrorCount(), "no error notification should be sent on success")
	sentMessages := cmdNotifier.SentMessages()
	require.Len(t, sentMessages, 1, "panel login must send exactly one $/snyk.hasAuthenticated notification")
	authParams, ok := sentMessages[0].(types.AuthenticationParams)
	require.True(t, ok, "notification payload must be AuthenticationParams")
	assert.NotEmpty(t, authParams.Token, "notification must carry a non-empty token")
	assert.Equal(t, c.SnykApi(), authParams.ApiUrl, "notification must carry the current API URL")
	assert.Equal(t, authParams.Token, c.Token(), "panel login must persist the token in LS config")
}

func TestLoginCommand_Execute_ThreeArgs_EmptyTokenFromAuth_SendsNoNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	provider.ReturnEmptyToken = true
	cmd, cmdNotifier := setupLoginCmd(t, c, provider, []any{"fake", "https://api.snyk.io", false})

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.Equal(t, 0, cmdNotifier.SendErrorCount(), "no error notification should be sent when auth returns empty token")
	for _, msg := range cmdNotifier.SentMessages() {
		if p, ok := msg.(types.AuthenticationParams); ok {
			assert.NotEmpty(t, p.Token, "hasAuthenticated must never be sent with an empty token")
		}
	}
}

func TestLoginCommand_Execute_ZeroArgs_EmptyTokenFromAuth_SendsNoNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetAuthenticationMethod(types.FakeAuthentication)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	provider.ReturnEmptyToken = true
	cmd, cmdNotifier := setupLoginCmd(t, c, provider, []any{})

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.Equal(t, 0, cmdNotifier.SendErrorCount(), "no error notification should be sent when auth returns empty token")
	for _, msg := range cmdNotifier.SentMessages() {
		if p, ok := msg.(types.AuthenticationParams); ok {
			assert.NotEmpty(t, p.Token, "hasAuthenticated must never be sent with an empty token")
		}
	}
}

func TestLoginCommand_Execute_InvalidArgCount_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	cmd, _ := setupLoginCmd(t, c, provider, []any{"only-one-arg"})

	result, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "0 or 3")
}

func TestLoginCommand_Execute_WrongAuthMethodType_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	// Pass an int instead of string for authMethod (args[0]) to trigger type assertion failure.
	cmd, _ := setupLoginCmd(t, c, provider, []any{123, "https://api.snyk.io", false})

	result, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a string")
}

func TestLoginCommand_Execute_WrongEndpointType_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	// Pass an int instead of string for endpoint (args[1]) to trigger type assertion failure.
	cmd, _ := setupLoginCmd(t, c, provider, []any{"fake", 9000, false})

	result, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a string")
}

func TestLoginCommand_Execute_WrongInsecureType_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	// Pass a string instead of bool for insecure (args[2]) to trigger type assertion failure.
	cmd, _ := setupLoginCmd(t, c, provider, []any{"fake", "https://api.snyk.io", "false"})

	result, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a bool")
}

func TestLoginCommand_Execute_ThreeArgs_AppliesEndpointToConfig(t *testing.T) {
	const newEndpoint = "https://api.eu.snyk.io"
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	cmd, _ := setupLoginCmd(t, c, provider, []any{"fake", newEndpoint, false})

	_, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	// The endpoint must be applied to the LS config before authentication.
	assert.Equal(t, newEndpoint, c.SnykApi(), "endpoint must be applied to LS config")
}

func TestLoginCommand_Execute_ThreeArgs_AppliesAuthMethodToConfig(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	cmd, _ := setupLoginCmd(t, c, provider, []any{"fake", c.SnykApi(), false})

	_, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	// The auth method must be applied to the LS config before authentication.
	assert.Equal(t, types.FakeAuthentication, c.AuthenticationMethod(), "auth method must be applied to LS config")
}
