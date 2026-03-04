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

// setupLoginCmd creates a loginCommand. cmdNotifier receives SendError calls when the command encounters an error.
func setupLoginCmd(
	t *testing.T,
	c *config.Config,
	provider authentication.AuthenticationProvider,
	args []any,
) (loginCommand, *notification.MockNotifier) {
	t.Helper()
	cmdNotifier := notification.NewMockNotifier()
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())
	cmd := loginCommand{
		command:     types.CommandData{CommandId: types.LoginCommand, Arguments: args},
		authService: authService,
		notifier:    cmdNotifier,
		c:           c,
	}
	return cmd, cmdNotifier
}

func TestLoginCommand_Execute_ThreeArgs_SendsNotificationAndReturnsNil(t *testing.T) {
	const endpoint = "https://api.snyk.io"
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	cmd, cmdNotifier := setupLoginCmd(t, c, provider, []any{"fake", endpoint, false})

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.Nil(t, result, "settings page login must return nil — token is delivered via $/snyk.hasAuthenticated notification")
	assert.Equal(t, 0, cmdNotifier.SendErrorCount(), "no error notification should be sent on success")
	sentMessages := cmdNotifier.SentMessages()
	require.Len(t, sentMessages, 1, "settings page login must send exactly one $/snyk.hasAuthenticated notification")
	authParams, ok := sentMessages[0].(types.AuthenticationParams)
	require.True(t, ok, "notification payload must be AuthenticationParams")
	assert.NotEmpty(t, authParams.Token, "notification must carry a non-empty token")
	assert.Equal(t, endpoint, authParams.ApiUrl, "notification must carry the endpoint as ApiUrl")
	assert.False(t, authParams.Persist, "settings page login notification must have Persist=false")
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
	assert.True(t, authParams.Persist, "panel login notification must have Persist=true")
	assert.Equal(t, authParams.Token, c.Token(), "panel login must persist the token in LS config")
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

func TestLoginCommand_Execute_AuthServiceError_ReturnsErrorAndNotifiesUser(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	// "unknown-method" causes selectProvider to return an error → auth service propagates it to the command.
	cmd, cmdNotifier := setupLoginCmd(t, c, provider, []any{"unknown-method", "https://api.snyk.io", false})

	result, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "unsupported authentication method")
	assert.GreaterOrEqual(t, cmdNotifier.SendErrorCount(), 1, "user must be notified when auth service returns an error")
}

func TestLoginCommand_Execute_UnrecognizedAuthMethod_ExistingTokenPreserved(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	existingToken := "existing-test-token"
	c.SetToken(existingToken)
	cmd, _ := setupLoginCmd(t, c, provider, []any{"unknown-method", "https://api.snyk.io", false})

	_, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported authentication method")
	assert.Equal(t, existingToken, c.Token(), "existing token must be preserved when auth method is unrecognized")
}
