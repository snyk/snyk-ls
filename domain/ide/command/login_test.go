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

// setupLoginCmd creates a loginCommand wired with two separate notifiers:
// authServiceNotifier receives AuthenticationParams on successful authentication (becomes $/snyk.hasAuthenticated).
// cmdNotifier receives SendError calls when the command itself encounters an error.
func setupLoginCmd(
	t *testing.T,
	c *config.Config,
	provider authentication.AuthenticationProvider,
	args []any,
) (loginCommand, *notification.MockNotifier, *notification.MockNotifier) {
	t.Helper()
	authServiceNotifier := notification.NewMockNotifier()
	cmdNotifier := notification.NewMockNotifier()
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), authServiceNotifier)
	cmd := loginCommand{
		command:     types.CommandData{CommandId: types.LoginCommand, Arguments: args},
		authService: authService,
		notifier:    cmdNotifier,
		c:           c,
	}
	return cmd, authServiceNotifier, cmdNotifier
}

func TestLoginCommand_Execute_ValidArgs_ReturnsTokenAndSendsAuthNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	cmd, authServiceNotifier, cmdNotifier := setupLoginCmd(t, c, provider, []any{"fake", "https://api.snyk.io", false})

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	token, ok := result.(string)
	assert.True(t, ok, "result should be a string token")
	assert.NotEmpty(t, token)
	assert.Equal(t, 0, cmdNotifier.SendErrorCount(), "no error notification should be sent on success")

	// Auth service sends AuthenticationParams on success; this triggers $/snyk.hasAuthenticated in production.
	var hasAuthParams bool
	for _, m := range authServiceNotifier.SentMessages() {
		if _, ok := m.(types.AuthenticationParams); ok {
			hasAuthParams = true
			break
		}
	}
	assert.True(t, hasAuthParams, "expected AuthenticationParams notification to be sent by auth service on success")
}

func TestLoginCommand_Execute_MissingArgs_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	cmd, authServiceNotifier, _ := setupLoginCmd(t, c, provider, []any{})

	result, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "3 arguments")
	assert.Equal(t, 0, authServiceNotifier.SendCount(), "auth service must not be called when arguments are missing")
}

func TestLoginCommand_Execute_WrongAuthMethodType_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	// Pass an int instead of string for authMethod (args[0]) to trigger type assertion failure.
	cmd, authServiceNotifier, _ := setupLoginCmd(t, c, provider, []any{123, "https://api.snyk.io", false})

	result, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a string")
	assert.Equal(t, 0, authServiceNotifier.SendCount(), "auth service must not be called when arg type is wrong")
}

func TestLoginCommand_Execute_WrongEndpointType_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	// Pass an int instead of string for endpoint (args[1]) to trigger type assertion failure.
	cmd, authServiceNotifier, _ := setupLoginCmd(t, c, provider, []any{"fake", 9000, false})

	result, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a string")
	assert.Equal(t, 0, authServiceNotifier.SendCount(), "auth service must not be called when endpoint arg type is wrong")
}

func TestLoginCommand_Execute_WrongInsecureType_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	// Pass a string instead of bool for insecure (args[2]) to trigger type assertion failure.
	cmd, authServiceNotifier, _ := setupLoginCmd(t, c, provider, []any{"fake", "https://api.snyk.io", "false"})

	result, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "must be a bool")
	assert.Equal(t, 0, authServiceNotifier.SendCount(), "auth service must not be called when insecure arg type is wrong")
}

func TestLoginCommand_Execute_AuthServiceError_ReturnsErrorAndNotifiesUser(t *testing.T) {
	c := testutil.UnitTest(t)
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	// "unknown-method" causes selectProvider to return an error → auth service propagates it to the command.
	cmd, _, cmdNotifier := setupLoginCmd(t, c, provider, []any{"unknown-method", "https://api.snyk.io", false})

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
	cmd, _, _ := setupLoginCmd(t, c, provider, []any{"unknown-method", "https://api.snyk.io", false})

	_, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported authentication method")
	assert.Equal(t, existingToken, c.Token(), "existing token must be preserved when auth method is unrecognized")
}
