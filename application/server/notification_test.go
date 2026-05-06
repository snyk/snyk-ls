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
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestCreateProgressListener(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
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

	server := mock_types.NewMockServer(ctrl)

	var called atomic.Bool

	server.EXPECT().
		Callback(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, s string, v any) (*jrpc2.Response, error) {
			called.Store(true)
			return nil, nil
		}).
		Times(1)

	server.EXPECT().
		Notify(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, s string, v any) (*jrpc2.Response, error) {
			called.Store(true)
			return nil, nil
		}).
		Times(1)

	listener := createProgressListener(progressChannel, server, engine.GetLogger())
	t.Cleanup(listener.Dispose)

	assert.Eventually(t, func() bool {
		return called.Load()
	}, 2*time.Second, time.Millisecond)

	listener.Dispose()
}

func TestProgressListenersCanBeDisposedIndependently(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	logger := engine.GetLogger()

	firstChannel := make(chan types.ProgressParams, 1)
	secondChannel := make(chan types.ProgressParams, 1)
	firstServer := mock_types.NewMockServer(ctrl)
	secondServer := mock_types.NewMockServer(ctrl)

	var secondCalled atomic.Bool
	secondServer.EXPECT().
		Notify(gomock.Any(), "$/progress", gomock.Any()).
		DoAndReturn(func(ctx context.Context, method string, params any) (*jrpc2.Response, error) {
			secondCalled.Store(true)
			return nil, nil
		}).
		Times(1)

	firstListener := createProgressListener(firstChannel, firstServer, logger)
	secondListener := createProgressListener(secondChannel, secondServer, logger)
	t.Cleanup(secondListener.Dispose)

	firstListener.Dispose()

	secondChannel <- types.ProgressParams{
		Token: "second-token",
		Value: types.WorkDoneProgressReport{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressReportKind},
			Message:              "still running",
		},
	}

	assert.Eventually(t, func() bool {
		return secondCalled.Load()
	}, 2*time.Second, time.Millisecond)
}

func TestProgressListenerDisposeDoesNotWaitForBlockedCallback(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	progressChannel := make(chan types.ProgressParams, 1)
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	disposeReturned := make(chan struct{})

	progressChannel <- types.ProgressParams{
		Token: "blocked-callback-token",
		Value: types.WorkDoneProgressBegin{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressBeginKind},
			Title:                "title",
		},
	}

	server := mock_types.NewMockServer(ctrl)
	server.EXPECT().
		Callback(gomock.Any(), "window/workDoneProgress/create", gomock.Any()).
		DoAndReturn(func(ctx context.Context, method string, params any) (*jrpc2.Response, error) {
			close(callbackStarted)
			<-releaseCallback
			return nil, nil
		}).
		Times(1)
	server.EXPECT().
		Notify(gomock.Any(), "$/progress", gomock.Any()).
		AnyTimes()

	listener := createProgressListener(progressChannel, server, engine.GetLogger())
	t.Cleanup(func() {
		close(releaseCallback)
		listener.Dispose()
	})

	<-callbackStarted
	go func() {
		listener.Dispose()
		close(disposeReturned)
	}()

	assert.Eventually(t, func() bool {
		select {
		case <-disposeReturned:
			return true
		default:
			return false
		}
	}, 200*time.Millisecond, time.Millisecond)
}

func TestProgressListenerDisposeDoesNotWaitForBlockedNotify(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	progressChannel := make(chan types.ProgressParams, 1)
	notifyStarted := make(chan struct{})
	releaseNotify := make(chan struct{})
	disposeReturned := make(chan struct{})

	progressChannel <- types.ProgressParams{
		Token: "blocked-notify-token",
		Value: types.WorkDoneProgressReport{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressReportKind},
			Message:              "notify blocks",
		},
	}

	server := mock_types.NewMockServer(ctrl)
	server.EXPECT().
		Notify(gomock.Any(), "$/progress", gomock.Any()).
		DoAndReturn(func(ctx context.Context, method string, params any) (*jrpc2.Response, error) {
			close(notifyStarted)
			<-releaseNotify
			return nil, nil
		}).
		Times(1)

	listener := createProgressListener(progressChannel, server, engine.GetLogger())
	t.Cleanup(func() {
		close(releaseNotify)
		listener.Dispose()
	})

	<-notifyStarted
	go func() {
		listener.Dispose()
		close(disposeReturned)
	}()

	assert.Eventually(t, func() bool {
		select {
		case <-disposeReturned:
			return true
		default:
			return false
		}
	}, 200*time.Millisecond, time.Millisecond)
}

func TestProgressListenerStoreReplaceStopsPreviousBeforeStartingReplacement(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	logger := engine.GetLogger()
	progressChannel := make(chan types.ProgressParams, 1)
	store := &progressListenerStore{}

	firstServer := mock_types.NewMockServer(ctrl)
	secondServer := mock_types.NewMockServer(ctrl)
	var secondCalled atomic.Bool

	firstListener := createProgressListener(progressChannel, firstServer, logger)
	store.Replace(func() *progressListener {
		return firstListener
	})
	t.Cleanup(store.Dispose)

	firstServer.EXPECT().
		Notify(gomock.Any(), "$/progress", gomock.Any()).
		Times(0)
	secondServer.EXPECT().
		Notify(gomock.Any(), "$/progress", gomock.Any()).
		DoAndReturn(func(ctx context.Context, method string, params any) (*jrpc2.Response, error) {
			secondCalled.Store(true)
			return nil, nil
		}).
		Times(1)

	previousStoppedBeforeReplacement := false
	store.Replace(func() *progressListener {
		select {
		case <-firstListener.done:
			previousStoppedBeforeReplacement = true
		default:
		}
		return createProgressListener(progressChannel, secondServer, logger)
	})
	assert.True(t, previousStoppedBeforeReplacement, "previous progress listener was not stopped before starting replacement")

	progressChannel <- types.ProgressParams{
		Token: "replacement-token",
		Value: types.WorkDoneProgressReport{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressReportKind},
			Message:              "replacement progress",
		},
	}

	assert.Eventually(t, func() bool {
		return secondCalled.Load()
	}, 2*time.Second, time.Millisecond)
}

func TestServerInitializeShouldStartProgressListener(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)

	clientParams := types.InitializeParams{
		Capabilities: types.ClientCapabilities{
			Window: types.WindowClientCapabilities{
				WorkDoneProgress: true,
			},
		},
	}

	rsp, err := loc.Client.Call(t.Context(), "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}
	var result types.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}

	progressTracker := progress.NewTracker(true, engine.GetLogger())
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
		time.Millisecond,
	)
}

func TestCancelProgress(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	expectedWorkdoneProgressCancelParams := types.WorkdoneProgressCancelParams{
		Token: "token",
	}
	_, err = loc.Client.Call(t.Context(), "window/workDoneProgress/cancel", expectedWorkdoneProgressCancelParams)
	if err != nil {
		t.Fatal(err)
	}

	assert.Eventually(t, func() bool {
		return progress.IsCanceled(expectedWorkdoneProgressCancelParams.Token)
	}, time.Second*5, time.Millisecond)
}

func TestWindowWorkDoneProgressCancelUsesInjectedBus(t *testing.T) {
	bus := progress.NewBus()
	logger := zerolog.Nop()
	tracker := bus.NewTestTracker(make(chan types.ProgressParams, 1), make(chan bool, 1), &logger)
	defaultTracker := progress.NewTestTracker(make(chan types.ProgressParams, 1), make(chan bool, 1), &logger)
	t.Cleanup(progress.CleanupChannels)

	err := cancelProgress(t.Context(), bus, types.WorkdoneProgressCancelParams{
		Token: tracker.GetToken(),
	})

	assert.NoError(t, err)
	assert.True(t, bus.IsCanceled(tracker.GetToken()))
	assert.False(t, progress.IsCanceled(defaultTracker.GetToken()))
}

func Test_NotifierShouldSendNotificationToClient(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var expected = types.AuthenticationParams{Token: "test token", ApiUrl: "https://api.snyk.io"}

	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

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
		time.Millisecond,
	)
}

func Test_IsAvailableCliNotification(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var expected = types.SnykIsAvailableCli{CliPath: filepath.Join(t.TempDir(), "cli")}
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)
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
		time.Millisecond,
	)
}

func TestShowMessageRequest(t *testing.T) {
	t.Run("should send request to client", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		loc, jsonRPCRecorder := setupServer(t, engine, tokenService)

		_, err := loc.Client.Call(t.Context(), "initialize", nil)
		if err != nil {
			t.Fatal(err)
		}
		engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)
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
			time.Millisecond,
		)
	})

	t.Run("should execute a command when action item is selected", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		selectedAction := "Open browser"
		loc, _ := setupCustomServer(t, engine, tokenService, func(_ context.Context, _ *jrpc2.Request) (any, error) {
			return types.MessageActionItem{
				Title: selectedAction,
			}, nil
		})
		_, err := loc.Client.Call(t.Context(), "initialize", nil)
		if err != nil {
			t.Fatal(err)
		}
		command.SetService(types.NewCommandServiceMock())
		actionCommandMap := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()

		actionCommandMap.Add(types.MessageAction(selectedAction), types.CommandData{CommandId: types.OpenBrowserCommand, Arguments: []any{"https://snyk.io"}})

		request := types.ShowMessageRequest{Message: "message", Type: types.Info, Actions: actionCommandMap}
		engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)
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
			time.Millisecond,
		)
	})
}
