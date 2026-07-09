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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestRegisterNotifier_NilNotifier_Panics(t *testing.T) {
	// registerNotifier has "notifier" in its name; a nil notifier is a programming error
	// that must be caught at initialization time — not silently produce no-op behavior.
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	srv := mock_types.NewMockServer(ctrl)

	assert.Panics(t, func() {
		registerNotifier(conf, engine, testutil.DefaultConfigResolver(engine), logger, srv, nil)
	}, "registerNotifier must panic when notifier is nil")
}

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

	var callbackCalled atomic.Bool
	var notifyCalled atomic.Bool

	server.EXPECT().
		Callback(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, s string, v any) (*jrpc2.Response, error) {
			callbackCalled.Store(true)
			return nil, nil
		}).
		Times(1)

	server.EXPECT().
		Notify(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, s string, v any) (*jrpc2.Response, error) {
			notifyCalled.Store(true)
			return nil, nil
		}).
		Times(1)

	go createProgressListener(progressChannel, server, engine.GetLogger())

	assert.Eventually(t, func() bool {
		return callbackCalled.Load() && notifyCalled.Load()
	}, 2*time.Second, time.Millisecond)

	disposeProgressListener()
}

func TestServerInitializeShouldStartProgressListener(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

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
	loc, _, _ := setupServer(t, engine, tokenService)

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

// IDE-1035 (D): window/workDoneProgress/cancel for a non-scan token (e.g. a
// download tracker) must NOT reset the summary panel. The positive case (scan
// token → panel is eventually reset) is exercised by
// TestScan_CancelCallback_CalledAfterGoroutinesFinish in the scanner package,
// which verifies the reset happens only after scan goroutines finish writing.
func TestCancelProgress_NonScanToken_DoesNotResetAggregator(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)

	agg := &initRecordingAggregator{}
	loc, _, _ := setupServer(t, engine, tokenService, WithDeps(di.Dependencies{ScanStateAggregator: agg}))

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)

	// Seed a workspace folder.
	tmpDir := types.FilePath(t.TempDir())
	_, _ = workspaceutil.SetupWorkspace(t, engine, tmpDir)

	// Create a plain (non-scan) tracker, e.g. for a download, and cancel it.
	plainTracker := progress.NewTracker(true, engine.GetLogger())
	cancelParams := types.WorkdoneProgressCancelParams{Token: plainTracker.GetToken()}
	_, err = loc.Client.Call(t.Context(), "window/workDoneProgress/cancel", cancelParams)
	require.NoError(t, err)

	// Give the handler time to execute; Init must NOT be called.
	assert.Never(t, func() bool {
		agg.mu.Lock()
		defer agg.mu.Unlock()
		return len(agg.initCalls) > 0
	}, 300*time.Millisecond, time.Millisecond, "Init must NOT be called when a non-scan token is canceled")
}

func Test_NotifierShouldSendNotificationToClient(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

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
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

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
		loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

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
		loc, _, _ := setupServer(t, engine, tokenService, WithCallback(func(_ context.Context, _ *jrpc2.Request) (any, error) {
			return types.MessageActionItem{
				Title: selectedAction,
			}, nil
		}))
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

func Test_registerNotifier_AuthenticationSendsConfiguration(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	// Trigger via real auth service so the full registerNotifier path fires.
	di.AuthenticationService().UpdateCredentials("config-send-test-token", true, false)

	assert.Eventually(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")) > 0 &&
				len(jsonRPCRecorder.FindNotificationsByMethod("$/snyk.configuration")) > 0
		},
		2*time.Second,
		time.Millisecond,
		"expected both $/snyk.hasAuthenticated and $/snyk.configuration after authentication",
	)
}

func Test_NotifierWaitsForLspInitializedChannel(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	conf := engine.GetConfiguration()
	// Replace the channel set by initializeHandler; the previous channel has no waiters and is GC'd.
	types.NewLspInitializedChannel(conf)

	expected := types.AuthenticationParams{Token: "channel-wait-test", ApiUrl: "https://api.snyk.io"}
	di.Notifier().Send(expected)

	delivered := func() bool {
		for _, n := range jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated") {
			var actual types.AuthenticationParams
			_ = n.UnmarshalParams(&actual)
			if actual == expected {
				return true
			}
		}
		return false
	}
	assert.Never(t, delivered, 200*time.Millisecond, 10*time.Millisecond,
		"notification must not be delivered before LspInitialized is signaled")

	types.SignalLspInitialized(conf)

	assert.Eventually(t, delivered, 2*time.Second, time.Millisecond,
		"notification must be delivered after LspInitialized is signaled")
}
