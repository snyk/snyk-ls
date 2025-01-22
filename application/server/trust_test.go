/*
 * © 2022-2023 Snyk Limited
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

	"github.com/snyk/snyk-ls/domain/snyk/scanner"

	"github.com/creachadair/jrpc2"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_handleUntrustedFolders_shouldTriggerTrustRequestAndNotScan(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServer(t, c)
	sc := &scanner.TestScanner{}
	c.SetTrustedFolderFeatureEnabled(true)
	c.Workspace().AddFolder(workspace.NewFolder(c, "dummy", "dummy", sc, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.StateAggregator()))
	command.HandleUntrustedFolders(c, context.Background(), loc.Server)

	assert.True(t, checkTrustMessageRequest(jsonRPCRecorder, c))
	assert.Equal(t, sc.Calls(), 0)
}

func Test_handleUntrustedFolders_shouldNotTriggerTrustRequestWhenAlreadyRequesting(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServer(t, c)
	w := c.Workspace()
	sc := &scanner.TestScanner{}
	c.SetTrustedFolderFeatureEnabled(true)
	w.AddFolder(workspace.NewFolder(c, "dummy", "dummy", sc, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.StateAggregator()))
	w.StartRequestTrustCommunication()

	command.HandleUntrustedFolders(c, context.Background(), loc.Server)

	assert.Len(t, jsonRPCRecorder.FindCallbacksByMethod("window/showMessageRequest"), 0)
	assert.Equal(t, sc.Calls(), 0)
}

func Test_handleUntrustedFolders_shouldTriggerTrustRequestAndScanAfterConfirmation(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupCustomServer(t, c, func(_ context.Context, _ *jrpc2.Request) (any, error) {
		return types.MessageActionItem{
			Title: command.DoTrust,
		}, nil
	})
	registerNotifier(c, loc.Server)

	w := c.Workspace()
	sc := &scanner.TestScanner{}
	c.SetTrustedFolderFeatureEnabled(true)
	w.AddFolder(workspace.NewFolder(c, "/trusted/dummy", "dummy", sc, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.StateAggregator()))

	command.HandleUntrustedFolders(c, context.Background(), loc.Server)

	assert.Eventually(t, func() bool {
		addTrustedSent := len(jsonRPCRecorder.FindNotificationsByMethod("$/snyk.addTrustedFolders")) == 1
		return sc.Calls() == 1 && addTrustedSent
	}, time.Second, time.Millisecond)
}

func Test_handleUntrustedFolders_shouldTriggerTrustRequestAndNotScanAfterNegativeConfirmation(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, _ := setupCustomServer(t, c, func(_ context.Context, _ *jrpc2.Request) (any, error) {
		return types.MessageActionItem{
			Title: command.DontTrust,
		}, nil
	})
	registerNotifier(c, loc.Server)
	w := c.Workspace()
	sc := &scanner.TestScanner{}
	w.AddFolder(workspace.NewFolder(c, "/trusted/dummy", "dummy", sc, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.StateAggregator()))
	c.SetTrustedFolderFeatureEnabled(true)

	command.HandleUntrustedFolders(c, context.Background(), loc.Server)

	assert.Equal(t, sc.Calls(), 0)
}

func Test_initializeHandler_shouldCallHandleUntrustedFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetTrustedFolderFeatureEnabled(true)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	_, err := loc.Client.Call(context.Background(), "initialize", types.InitializeParams{
		RootURI: uri.PathToUri("/untrusted/dummy"),
	})
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder, c) }, time.Second, time.Millisecond)
}

func Test_DidWorkspaceFolderChange_shouldCallHandleUntrustedFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetTrustedFolderFeatureEnabled(true)

	_, err := loc.Client.Call(context.Background(), "workspace/didChangeWorkspaceFolders", types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Added: []types.WorkspaceFolder{
				{Uri: uri.PathToUri("/untrusted/dummy"), Name: "dummy"},
			},
			Removed: []types.WorkspaceFolder{},
		},
	})

	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder, c) }, time.Second, time.Millisecond)
}

func Test_MultipleFoldersInRootDirWithOnlyOneTrusted(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServer(t, c)

	c.SetTrustedFolderFeatureEnabled(true)

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	rootDir := t.TempDir()

	// create trusted repo
	repo1, err := testutil.SetupCustomTestRepo(t, rootDir, nodejsGoof, "0336589", c.Logger())
	assert.NoError(t, err)

	// create untrusted directory in same rootDir with the exact prefix
	exploitDir := repo1 + "-exploit"
	err = os.MkdirAll(exploitDir, 0755)
	assert.NoError(t, err)

	// only trust first dir
	c.SetTrustedFolders([]string{repo1})

	_, err = loc.Client.Call(context.Background(), "initialize", types.InitializeParams{
		RootURI: uri.PathToUri(exploitDir),
	})
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder, c) }, time.Second*10, time.Millisecond)
}

func checkTrustMessageRequest(jsonRPCRecorder *testutil.JsonRPCRecorder, c *config.Config) bool {
	callbacks := jsonRPCRecorder.FindCallbacksByMethod("window/showMessageRequest")
	if len(callbacks) == 0 {
		return false
	}
	var params types.ShowMessageRequestParams
	_ = callbacks[0].UnmarshalParams(&params)
	_, untrusted := c.Workspace().GetFolderTrust()
	return params.Type == types.Warning && params.Message == command.GetTrustMessage(untrusted)
}
