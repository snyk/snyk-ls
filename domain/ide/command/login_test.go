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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
func setMockWorkspace(t *testing.T, ctrl *gomock.Controller, c interface{ SetWorkspace(types.Workspace) }) {
	t.Helper()
	mockWs := mock_types.NewMockWorkspace(ctrl)
	mockWs.EXPECT().Folders().Return([]types.Folder{}).AnyTimes()
	c.SetWorkspace(mockWs)
}

func TestLoginCommand_Execute_NoArgs_AuthenticatesNormally(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	setMockWorkspace(t, ctrl, c)

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)
	mockLdxSync.EXPECT().RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	cmd := loginCommand{
		command:            types.CommandData{CommandId: types.LoginCommand},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		c:                  c,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestLoginCommand_Execute_ThreeArgs_AppliesConfigBeforeAuth(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	setMockWorkspace(t, ctrl, c)

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)
	mockLdxSync.EXPECT().RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{"fake", "https://api.snyk.io", false},
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		c:                  c,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, types.FakeAuthentication, c.AuthenticationMethod())
}

func TestLoginCommand_Execute_ThreeArgs_InsecureAsString(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	setMockWorkspace(t, ctrl, c)

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)
	mockLdxSync.EXPECT().RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{"fake", "https://api.snyk.io", "true"},
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		c:                  c,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestLoginCommand_Execute_InvalidAuthMethodArg_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{123, "https://api.snyk.io", false}, // invalid: int instead of string
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		c:                  c,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestLoginCommand_Execute_InvalidInsecureArg_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	provider := authentication.NewFakeCliAuthenticationProvider(c)
	authService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())
	mockLdxSync := mock_command.NewMockLdxSyncService(ctrl)

	cmd := loginCommand{
		command: types.CommandData{
			CommandId: types.LoginCommand,
			Arguments: []any{"oauth", "https://api.snyk.io", 42}, // invalid: int instead of bool/string
		},
		authService:        authService,
		featureFlagService: featureflag.NewFakeService(),
		notifier:           notification.NewMockNotifier(),
		c:                  c,
		ldxSyncService:     mockLdxSync,
	}

	result, err := cmd.Execute(t.Context())

	require.Error(t, err)
	assert.Nil(t, result)
}
