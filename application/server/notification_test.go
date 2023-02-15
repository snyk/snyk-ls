/*
 * © 2022 Snyk Limited All rights reserved.
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
	"reflect"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
)

type ServerImplMock struct{}

var notified = concurrency.AtomicBool{}

func (b *ServerImplMock) Callback(_ context.Context,
	_ string,
	_ any,
) (*jrpc2.Response, error) { // todo: check if better way exists, mocking? go mock / testify
	notified.Set(true)
	return nil, nil
}
func (b *ServerImplMock) Notify(_ context.Context, _ string, _ any) error {
	notified.Set(true)
	return nil
}

func TestCreateProgressListener(t *testing.T) {
	server := &ServerImplMock{}
	registerProgressHandler(server)
	progressNotification := lsp.ProgressParams{
		Token: "token",
		Value: lsp.WorkDoneProgressBegin{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "begin"},
			Title:                "title",
			Message:              "message",
			Cancellable:          true,
			Percentage:           0,
		},
	}
	progress.ProgressReported.Raise(progressNotification)

	defer func() { notified.Set(false) }()

	assert.True(t, notified.Get())
}

func TestServerInitializeShouldStartProgressListener(t *testing.T) {
	loc := setupServer(t)

	clientParams := lsp.InitializeParams{
		Capabilities: sglsp.ClientCapabilities{
			Window: sglsp.WindowClientCapabilities{
				WorkDoneProgress: true,
			},
		},
	}

	rsp, err := loc.Client.Call(ctx, "initialize", clientParams) // Blocks until initialized is finished
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err = rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}

	progressTracker := progress.NewTracker(true)
	progressTracker.Begin("title", "message")

	// should receive progress notification
	callbacks := jsonRPCRecorder.FindCallbacksByMethod("window/workDoneProgress/create")
	for _, c := range callbacks {
		actualProgress := lsp.ProgressParams{}
		_ = c.UnmarshalParams(&actualProgress)
		if progressTracker.GetToken() == actualProgress.Token {
			return // Pass the test
		}
	}
	assert.Fail(t, "No progress notification received")
}

func TestCancelProgress(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	expectedWorkdoneProgressCancelParams := lsp.WorkdoneProgressCancelParams{
		Token: "token",
	}

	notified := false
	notifier := &progress.CancelNotifier{Token: expectedWorkdoneProgressCancelParams.Token, CallBack: func(_ string) {
		notified = true
	}}
	progress.ProgressCancelled.Subscribe(notifier)
	_, err = loc.Client.Call(ctx, "window/workDoneProgress/cancel", expectedWorkdoneProgressCancelParams)

	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		return notified
	}, time.Second*5, time.Millisecond)
}

func Test_NotifierShouldSendNotificationToClient(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var expected = lsp.AuthenticationParams{Token: "test token"}

	notification.Send(expected)
	assert.Eventually(
		t,
		func() bool {
			notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")
			if len(notifications) < 1 {
				return false
			}
			for _, n := range notifications {
				var actual = lsp.AuthenticationParams{}
				_ = n.UnmarshalParams(&actual)
				if reflect.DeepEqual(expected, actual) {
					return true
				}
			}
			return false
		},
		2*time.Second,
		10*time.Millisecond,
	)
}

func Test_IsAvailableCliNotification(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var expected = lsp.SnykIsAvailableCli{CliPath: "path"}

	notification.Send(expected)
	assert.Eventually(
		t,
		func() bool {
			notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.isAvailableCli")
			if len(notifications) < 1 {
				return false
			}
			for _, n := range notifications {
				var actual = lsp.SnykIsAvailableCli{}
				_ = n.UnmarshalParams(&actual)
				if reflect.DeepEqual(expected, actual) {
					return true
				}
			}
			return false
		},
		2*time.Second,
		10*time.Millisecond,
	)
}

func TestShowMessageRequest(t *testing.T) {
	t.Run("should send request to client", func(t *testing.T) {
		loc := setupServer(t)

		_, err := loc.Client.Call(ctx, "initialize", nil)
		if err != nil {
			t.Fatal(err)
		}

		actionCommandMap := data_structure.NewOrderedMap[snyk.MessageAction, snyk.CommandInterface]()
		expectedTitle := "test title"
		actionCommandMap.Add(snyk.MessageAction(expectedTitle), command.NewOpenBrowserCommand("https://snyk.io"))

		expected := snyk.ShowMessageRequest{Message: "message", Type: snyk.Info, Actions: actionCommandMap}

		notification.Send(expected)

		assert.Eventually(
			t,
			func() bool {
				callbacks := jsonRPCRecorder.FindCallbacksByMethod("window/showMessageRequest")
				if len(callbacks) < 1 {
					return false
				}
				var actual lsp.ShowMessageRequestParams
				_ = callbacks[0].UnmarshalParams(&actual)
				_, ok := expected.Actions.Get(snyk.MessageAction(expectedTitle))
				return ok &&
					expected.Message == actual.Message &&
					int(expected.Type) == int(actual.Type)
			},
			2*time.Second,
			10*time.Millisecond,
		)
	})

	t.Run("should execute a command when action item is selected", func(t *testing.T) {
		selectedAction := "Open browser"
		loc := setupCustomServer(t, func(_ context.Context, _ *jrpc2.Request) (any, error) {
			return lsp.MessageActionItem{
				Title: selectedAction,
			}, nil
		})
		_, err := loc.Client.Call(ctx, "initialize", nil)
		if err != nil {
			t.Fatal(err)
		}

		actionCommandMap := data_structure.NewOrderedMap[snyk.MessageAction, snyk.CommandInterface]()
		actionCommandMap.Add(snyk.MessageAction(selectedAction), command.NewOpenBrowserCommand("https://snyk.io"))

		request := snyk.ShowMessageRequest{Message: "message", Type: snyk.Info, Actions: actionCommandMap}

		notification.Send(request)

		assert.Eventually(
			t,
			func() bool {
				// verify that passed command is eventually executed
				commandService := di.CommandService()
				commandServiceMock := commandService.(*snyk.CommandServiceMock)
				return commandServiceMock.ExecutedCommands()[0].Command().CommandId == snyk.OpenBrowserCommand
			},
			2*time.Second,
			10*time.Millisecond,
		)
	})
}
