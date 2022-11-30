/*
 * Copyright 2022 Snyk Ltd.
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
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_handleUntrustedFolders_shouldTriggerTrustRequestAndNotScan(t *testing.T) {
	loc := setupServer(t)
	w := workspace.Get()
	scanner := &snyk.TestScanner{}
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	w.AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService()))
	handleUntrustedFolders(context.Background(), loc.Server)

	assert.True(t, checkTrustMessageRequest())
	assert.Equal(t, scanner.Calls(), 0)
}

func Test_handleUntrustedFolders_shouldNotTriggerTrustRequestWhenAlreadyRequesting(t *testing.T) {
	loc := setupServer(t)
	w := workspace.Get()
	scanner := &snyk.TestScanner{}
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	w.AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService()))
	w.StartRequestTrustCommunication()

	handleUntrustedFolders(context.Background(), loc.Server)

	assert.Len(t, jsonRPCRecorder.FindCallbacksByMethod("window/showMessageRequest"), 0)
	assert.Equal(t, scanner.Calls(), 0)
}

func Test_handleUntrustedFolders_shouldTriggerTrustRequestAndScanAfterConfirmation(t *testing.T) {
	loc := setupCustomServer(t, func(_ context.Context, _ *jrpc2.Request) (interface{}, error) {
		return lsp.MessageActionItem{
			Title: doTrust,
		}, nil
	})
	registerNotifier(loc.Server)

	w := workspace.Get()
	scanner := &snyk.TestScanner{}
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	w.AddFolder(workspace.NewFolder("/trusted/dummy", "dummy", scanner, di.HoverService()))

	handleUntrustedFolders(context.Background(), loc.Server)

	assert.Eventually(t, func() bool {
		addTrustedSent := len(jsonRPCRecorder.FindNotificationsByMethod("$/snyk.addTrustedFolders")) == 1
		return scanner.Calls() == 1 && addTrustedSent
	}, time.Second, time.Millisecond)
}

func Test_handleUntrustedFolders_shouldTriggerTrustRequestAndNotScanAfterNegativeConfirmation(t *testing.T) {
	loc := setupCustomServer(t, func(_ context.Context, _ *jrpc2.Request) (interface{}, error) {
		return lsp.MessageActionItem{
			Title: dontTrust,
		}, nil
	})
	registerNotifier(loc.Server)
	w := workspace.Get()
	scanner := &snyk.TestScanner{}
	w.AddFolder(workspace.NewFolder("/trusted/dummy", "dummy", scanner, di.HoverService()))
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

	handleUntrustedFolders(context.Background(), loc.Server)

	assert.Equal(t, scanner.Calls(), 0)
}

func Test_initializeHandler_shouldCallHandleUntrustedFolders(t *testing.T) {
	loc := setupServer(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

	_, err := loc.Client.Call(context.Background(), "initialize", lsp.InitializeParams{
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
	assert.Eventually(t, func() bool { return checkTrustMessageRequest() }, time.Second, time.Millisecond)
}

func Test_DidWorkspaceFolderChange_shouldCallHandleUntrustedFolders(t *testing.T) {
	loc := setupServer(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

	_, err := loc.Client.Call(context.Background(), "workspace/didChangeWorkspaceFolders", lsp.DidChangeWorkspaceFoldersParams{
		Event: lsp.WorkspaceFoldersChangeEvent{
			Added: []lsp.WorkspaceFolder{
				{Uri: uri.PathToUri("/untrusted/dummy"), Name: "dummy"},
			},
			Removed: []lsp.WorkspaceFolder{},
		},
	})

	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest() }, time.Second, time.Millisecond)
}

func checkTrustMessageRequest() bool {
	callbacks := jsonRPCRecorder.FindCallbacksByMethod("window/showMessageRequest")
	if len(callbacks) == 0 {
		return false
	}
	var params lsp.ShowMessageRequestParams
	_ = callbacks[0].UnmarshalParams(&params)
	_, untrusted := workspace.Get().GetFolderTrust()
	return params.Type == lsp.Warning && params.Message == getTrustMessage(untrusted)
}
