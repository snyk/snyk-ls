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
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestCreateProgressListener(t *testing.T) {
	c := testutil.UnitTest(t)
	progressChannel := make(chan types.ProgressParams, 1)
	progressNotification := types.ProgressParams{
		Token: "token",
		Value: types.WorkDoneProgressBegin{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: "begin"},
			Title:                "title",
			Message:              "message",
			Cancellable:          true,
			Percentage:           0,
		},
	}
	progressChannel <- progressNotification

	server := ServerImplMock{}

	go createProgressListener(progressChannel, &server, c.Logger())
	defer func() { notified.Set(false) }()

	assert.Eventually(t, func() bool {
		return notified.Get()
	}, 2*time.Second, 10*time.Millisecond)

	disposeProgressListener()
}

func TestServerInitializeShouldStartProgressListener(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServer(t, c)

	clientParams := types.InitializeParams{
		Capabilities: types.ClientCapabilities{
			Window: types.WindowClientCapabilities{
				WorkDoneProgress: true,
			},
		},
	}

	rsp, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}
	var result types.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}

	progressTracker := progress.NewTracker(true)
	progressTracker.BeginWithMessage("title", "message")
	// should receive progress notification
	assert.Eventually(
		t,
		func() bool {
			callbacks := jsonRPCRecorder.FindCallbacksByMethod("window/workDoneProgress/create")
			for _, c := range callbacks {
				actualProgress := types.ProgressParams{}
				_ = c.UnmarshalParams(&actualProgress)
				if progressTracker.GetToken() == actualProgress.Token {
					return true
				}
			}
			return false
		},
		5*time.Second,
		10*time.Millisecond,
	)
}

func TestCancelProgress(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, _ := setupServer(t, c)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	expectedWorkdoneProgressCancelParams := types.WorkdoneProgressCancelParams{
		Token: "token",
	}
	_, err = loc.Client.Call(ctx, "window/workDoneProgress/cancel", expectedWorkdoneProgressCancelParams)
	if err != nil {
		t.Fatal(err)
	}

	assert.Eventually(t, func() bool {
		return progress.IsCanceled(expectedWorkdoneProgressCancelParams.Token)
	}, time.Second*5, time.Millisecond)
}

func Test_NotifierShouldSendNotificationToClient(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServer(t, c)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var expected = types.AuthenticationParams{Token: "test token", ApiUrl: "https://api.snyk.io"}

	c.SetLSPInitialized(true)

	di.Notifier().Send(expected)
	assert.Eventually(
		t,
		func() bool {
			notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")
			if len(notifications) < 1 {
				return false
			}
			for _, n := range notifications {
				var actual = types.AuthenticationParams{}
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
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServer(t, c)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var expected = types.SnykIsAvailableCli{CliPath: filepath.Join(t.TempDir(), "cli")}
	c.SetLSPInitialized(true)
	di.Notifier().Send(expected)
	assert.Eventually(
		t,
		func() bool {
			notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.isAvailableCli")
			if len(notifications) < 1 {
				return false
			}
			for _, n := range notifications {
				var actual = types.SnykIsAvailableCli{}
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
		c := testutil.UnitTest(t)
		loc, jsonRPCRecorder := setupServer(t, c)

		_, err := loc.Client.Call(ctx, "initialize", nil)
		if err != nil {
			t.Fatal(err)
		}
		c.SetLSPInitialized(true)
		actionCommandMap := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()
		expectedTitle := "test title"
		// data, err := command.CreateFromCommandData(snyk.CommandData{
		// 	CommandId: snyk.OpenBrowserCommand,
		// 	Arguments: []any{"https://snyk.io"},
		// }, loc.Server, di.AuthenticationService(), di.LearnService(), di.Notifier(), nil, nil)
		data := types.CommandData{
			CommandId: types.OpenBrowserCommand,
			Arguments: []any{"https://snyk.io"},
		}
		assert.NoError(t, err)
		actionCommandMap.Add(
			types.MessageAction(expectedTitle),
			data,
		)

		expected := types.ShowMessageRequest{Message: "message", Type: types.Info, Actions: actionCommandMap}

		di.Notifier().Send(expected)

		assert.Eventually(
			t,
			func() bool {
				callbacks := jsonRPCRecorder.FindCallbacksByMethod("window/showMessageRequest")
				if len(callbacks) < 1 {
					return false
				}
				var actual types.ShowMessageRequestParams
				_ = callbacks[0].UnmarshalParams(&actual)
				_, ok := expected.Actions.Get(types.MessageAction(expectedTitle))
				return ok &&
					expected.Message == actual.Message &&
					int(expected.Type) == int(actual.Type)
			},
			2*time.Second,
			10*time.Millisecond,
		)
	})

	t.Run("should execute a command when action item is selected", func(t *testing.T) {
		c := testutil.UnitTest(t)
		selectedAction := "Open browser"
		loc, _ := setupCustomServer(t, c, func(_ context.Context, _ *jrpc2.Request) (any, error) {
			return types.MessageActionItem{
				Title: selectedAction,
			}, nil
		})
		_, err := loc.Client.Call(ctx, "initialize", nil)
		if err != nil {
			t.Fatal(err)
		}
		command.SetService(types.NewCommandServiceMock())
		actionCommandMap := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()

		actionCommandMap.Add(types.MessageAction(selectedAction), types.CommandData{CommandId: types.OpenBrowserCommand, Arguments: []any{"https://snyk.io"}})

		request := types.ShowMessageRequest{Message: "message", Type: types.Info, Actions: actionCommandMap}
		c.SetLSPInitialized(true)
		di.Notifier().Send(request)

		assert.Eventually(
			t,
			func() bool {
				// verify that passed command is eventually executed
				commandService := command.Service()
				commandServiceMock := commandService.(*types.CommandServiceMock)
				executedCommands := commandServiceMock.ExecutedCommands()
				if len(executedCommands) == 0 {
					return false
				}
				return executedCommands[0].CommandId == types.OpenBrowserCommand
			},
			2*time.Second,
			10*time.Millisecond,
		)
	})
}
