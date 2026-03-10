/*
 * © 2022-2025 Snyk Limited
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
	"os"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_handleUntrustedFolders_shouldTriggerTrustRequestAndNotScan(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	sc := &scanner.TestScanner{}
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dummy"), "dummy", sc, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), featureflag.NewFakeService(), types.NewConfigResolver(engine.GetLogger()), engine))
	command.HandleUntrustedFolders(t.Context(), engine.GetConfiguration(), engine.GetLogger(), loc.Server)
	assert.Eventually(t, func() bool {
		return checkTrustMessageRequest(jsonRPCRecorder, engine) == true
	}, 5*time.Second, time.Millisecond)
	assert.Equal(t, sc.Calls(), 0)
}

func Test_handleUntrustedFolders_shouldNotTriggerTrustRequestWhenAlreadyRequesting(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	w := config.GetWorkspace(engine.GetConfiguration())
	sc := &scanner.TestScanner{}
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	w.AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dummy"), "dummy", sc, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), featureflag.NewFakeService(), types.NewConfigResolver(engine.GetLogger()), engine))
	w.StartRequestTrustCommunication()

	command.HandleUntrustedFolders(t.Context(), engine.GetConfiguration(), engine.GetLogger(), loc.Server)

	assert.Len(t, jsonRPCRecorder.FindCallbacksByMethod("window/showMessageRequest"), 0)
	assert.Equal(t, sc.Calls(), 0)
}

func Test_handleUntrustedFolders_shouldTriggerTrustRequestAndScanAfterConfirmation(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupCustomServer(t, engine, tokenService, func(_ context.Context, _ *jrpc2.Request) (any, error) {
		return types.MessageActionItem{
			Title: command.DoTrust,
		}, nil
	})
	conf := engine.GetConfiguration()
	registerNotifier(conf, engine.GetLogger(), loc.Server)

	w := config.GetWorkspace(engine.GetConfiguration())
	sc := &scanner.TestScanner{}
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingIsLspInitialized), true)
	w.AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("/trusted/dummy"), "dummy", sc, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), featureflag.NewFakeService(), types.NewConfigResolver(engine.GetLogger()), engine))

	command.HandleUntrustedFolders(t.Context(), engine.GetConfiguration(), engine.GetLogger(), loc.Server)

	assert.Eventually(t, func() bool {
		addTrustedSent := len(jsonRPCRecorder.FindNotificationsByMethod("$/snyk.addTrustedFolders")) == 1
		return sc.Calls() == 1 && addTrustedSent
	}, 2*time.Second, time.Millisecond)
}

func Test_handleUntrustedFolders_shouldTriggerTrustRequestAndNotScanAfterNegativeConfirmation(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupCustomServer(t, engine, tokenService, func(_ context.Context, _ *jrpc2.Request) (any, error) {
		return types.MessageActionItem{
			Title: command.DontTrust,
		}, nil
	})
	registerNotifier(engine.GetConfiguration(), engine.GetLogger(), loc.Server)
	w := config.GetWorkspace(engine.GetConfiguration())
	sc := &scanner.TestScanner{}
	w.AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("/trusted/dummy"), "dummy", sc, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), featureflag.NewFakeService(), types.NewConfigResolver(engine.GetLogger()), engine))
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	command.HandleUntrustedFolders(t.Context(), engine.GetConfiguration(), engine.GetLogger(), loc.Server)

	assert.Equal(t, sc.Calls(), 0)
}

func Test_initializeHandler_shouldCallHandleUntrustedFolders(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	_, err := loc.Client.Call(t.Context(), "initialize", types.InitializeParams{
		RootURI: uri.PathToUri("/untrusted/dummy"),
	})
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder, engine) }, time.Second, time.Millisecond)
}

func Test_DidWorkspaceFolderChange_shouldCallHandleUntrustedFolders(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	_, err := loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Added: []types.WorkspaceFolder{
				{Uri: uri.PathToUri("/untrusted/dummy"), Name: "dummy"},
			},
			Removed: []types.WorkspaceFolder{},
		},
	})

	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder, engine) }, time.Second, time.Millisecond)
}

func Test_MultipleFoldersInRootDirWithOnlyOneTrusted(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	rootDir := types.FilePath(t.TempDir())

	// create trusted repo
	repo1, err := storedconfig.SetupCustomTestRepo(t, rootDir, testsupport.NodejsGoof, "0336589", engine.GetLogger(), false)
	assert.NoError(t, err)

	// create untrusted directory in same rootDir with the exact prefix
	exploitDir := repo1 + "-exploit"
	err = os.MkdirAll(string(exploitDir), 0755)
	assert.NoError(t, err)

	// only trust first dir
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{repo1})

	_, err = loc.Client.Call(t.Context(), "initialize", types.InitializeParams{
		RootURI: uri.PathToUri(exploitDir),
	})
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder, engine) }, time.Second*10, time.Millisecond)
}

func checkTrustMessageRequest(jsonRPCRecorder *testsupport.JsonRPCRecorder, engine workflow.Engine) bool {
	callbacks := jsonRPCRecorder.FindCallbacksByMethod("window/showMessageRequest")
	if len(callbacks) == 0 {
		return false
	}
	var params types.ShowMessageRequestParams
	_ = callbacks[0].UnmarshalParams(&params)
	_, untrusted := config.GetWorkspace(engine.GetConfiguration()).GetFolderTrust()
	return params.Type == types.Warning && params.Message == command.GetTrustMessage(untrusted)
}
