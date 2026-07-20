/*
 * © 2023-2024 Snyk Limited
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
	"github.com/stretchr/testify/assert"

	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ExecuteCommand(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	resolver := types.NewConfigResolver(engine.GetLogger())
	authProvider := &authentication.FakeAuthenticationProvider{
		ExpectedAuthURL: "https://auth.url",
	}
	authenticationService := authentication.NewAuthenticationService(engine, tokenService, authProvider, nil, nil, resolver)
	service := NewService(engine, engine.GetLogger(), authenticationService, nil, nil, nil, nil, nil, nil, NewLdxSyncService(resolver), nil, nil)
	cmd := types.CommandData{
		CommandId: types.CopyAuthLinkCommand,
	}

	url, _ := service.ExecuteCommandData(t.Context(), cmd, nil)

	assert.Equal(t, "https://auth.url", url)
}

func Test_ExecuteCommand_CanceledCommand_ReturnsCancellationWithoutError(t *testing.T) {
	// A command the IDE cancels mid-flight (e.g. a login canceled via $/cancelRequest) must be
	// returned to the caller as a cancellation, not logged or surfaced as a failure.
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	setMockWorkspace(t, ctrl, conf)

	resolver := testutil.DefaultConfigResolver(engine)
	blockingProvider := authentication.NewBlockingFakeAuthProvider()
	notifier := notification.NewMockNotifier()
	authService := authentication.NewAuthenticationService(engine, tokenService, blockingProvider, error_reporting.NewTestErrorReporter(engine), notifier, resolver)

	service := NewService(engine, engine.GetLogger(), authService, featureflag.NewFakeService(), notifier, nil, nil, nil, nil, mock_command.NewMockLdxSyncService(ctrl), resolver, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	var result any
	var err error
	go func() {
		result, err = service.ExecuteCommandData(ctx, types.CommandData{CommandId: types.LoginCommand}, nil)
		close(done)
	}()

	select {
	case <-blockingProvider.Started:
	case <-time.After(5 * time.Second):
		t.Fatal("auth did not start in time")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ExecuteCommandData did not return after cancellation")
	}

	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, result)
	assert.Zero(t, notifier.SendErrorCount(), "a canceled command must not surface an error to the user")
}
