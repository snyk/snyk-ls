/*
 * © 2022-2026 Snyk Limited
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
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// ACC-004: the initialize result must advertise diagnosticProvider with
// workspaceDiagnostics:true so out-of-process LSP clients discover pull support.
func Test_initialize_advertisesDiagnosticProvider(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)

	var result types.InitializeResult
	require.NoError(t, rsp.UnmarshalResult(&result))

	require.NotNil(t, result.Capabilities.DiagnosticProvider,
		"server must advertise diagnosticProvider capability")
	assert.True(t, result.Capabilities.DiagnosticProvider.WorkspaceDiagnostics,
		"diagnosticProvider.workspaceDiagnostics must be true")
}

// INT-001: workspace/diagnostic is a registered method (no MethodNotFound).
func Test_workspaceDiagnostic_isRegistered(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "workspace/diagnostic", types.WorkspaceDiagnosticParams{})
	require.NoError(t, err)

	var result types.WorkspaceDiagnosticReport
	require.NoError(t, rsp.UnmarshalResult(&result))
	assert.NotNil(t, result.Items)
}

// INT-002: textDocument/diagnostic is a registered method (no MethodNotFound).
func Test_textDocumentDiagnostic_isRegistered(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "textDocument/diagnostic", types.DocumentDiagnosticParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: "file:///nonexistent.go"},
	})
	require.NoError(t, err)

	var result types.RelatedFullDocumentDiagnosticReport
	require.NoError(t, rsp.UnmarshalResult(&result))
	assert.Equal(t, "full", result.Kind)
}

// ACC-006: workspace/diagnostic returns empty items when no folders are in the workspace.
func Test_workspaceDiagnostic_emptyWorkspace(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "workspace/diagnostic", types.WorkspaceDiagnosticParams{})
	require.NoError(t, err)

	var result types.WorkspaceDiagnosticReport
	require.NoError(t, rsp.UnmarshalResult(&result))
	assert.Empty(t, result.Items)
}

// ACC-007: workspace/diagnostic skips folders that are not trusted.
func Test_workspaceDiagnostic_skipsUntrustedFolder(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService)

	// Enable trust feature — any folder not in SettingTrustedFolders is now untrusted.
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	folderPath := types.FilePath(t.TempDir())
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(
		engine.GetConfiguration(), engine.GetLogger(), folderPath,
		"untrusted",
		di.Scanner(),
		di.HoverService(),
		di.ScanNotifier(),
		di.Notifier(),
		di.ScanPersister(),
		di.ScanStateAggregator(),
		featureflag.NewFakeService(),
		di.ConfigResolver(),
		engine,
	))

	rsp, err := loc.Client.Call(t.Context(), "workspace/diagnostic", types.WorkspaceDiagnosticParams{})
	require.NoError(t, err)

	var result types.WorkspaceDiagnosticReport
	require.NoError(t, rsp.UnmarshalResult(&result))
	assert.Empty(t, result.Items, "untrusted folder must be skipped by workspace/diagnostic")
}

// ACC-009: textDocument/diagnostic returns a full empty report for a document
// that does not belong to any known workspace folder.
func Test_textDocumentDiagnostic_unknownDocumentReturnsEmpty(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "textDocument/diagnostic", types.DocumentDiagnosticParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: "file:///no/such/file.go"},
	})
	require.NoError(t, err)

	var result types.RelatedFullDocumentDiagnosticReport
	require.NoError(t, rsp.UnmarshalResult(&result))
	assert.Equal(t, "full", result.Kind)
	assert.Empty(t, result.Items)
}

// ACC-001+002: workspace/diagnostic returns the same finding set as textDocument/publishDiagnostics
// for the same scan state.
func Test_workspaceDiagnostic_returnsSameFindingSetAsPush(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider).IsAuthenticated = true

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	filePath, fileDir := code.TempWorkdirWithIssues(t)
	fileUri := sendFileSavedMessage(t, engine, filePath, fileDir, loc)

	require.Eventually(t,
		checkForPublishedDiagnostics(t, engine, uri.PathFromUri(fileUri), -1, jsonRPCRecorder),
		5*time.Second, time.Millisecond)

	// Collect push diagnostics for the scanned file URI.
	var pushItems []types.Diagnostic
	for _, n := range jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics") {
		var params types.PublishDiagnosticsParams
		_ = n.UnmarshalParams(&params)
		if params.URI == fileUri {
			pushItems = params.Diagnostics
		}
	}

	rsp, err := loc.Client.Call(t.Context(), "workspace/diagnostic", types.WorkspaceDiagnosticParams{})
	require.NoError(t, err)

	var wsResult types.WorkspaceDiagnosticReport
	require.NoError(t, rsp.UnmarshalResult(&wsResult))

	var pullItems []types.Diagnostic
	for _, item := range wsResult.Items {
		if item.URI == fileUri {
			pullItems = item.Items
		}
	}

	require.NotEmpty(t, pullItems, "workspace/diagnostic must return findings for the scanned file")
	assert.Equal(t, pushItems, pullItems,
		"pull and push must report byte-identical findings")
}

// ACC-003: textDocument/diagnostic returns the same file findings as the push path.
func Test_textDocumentDiagnostic_returnsFileFindings(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider).IsAuthenticated = true

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	filePath, fileDir := code.TempWorkdirWithIssues(t)
	fileUri := sendFileSavedMessage(t, engine, filePath, fileDir, loc)

	require.Eventually(t,
		checkForPublishedDiagnostics(t, engine, uri.PathFromUri(fileUri), -1, jsonRPCRecorder),
		5*time.Second, time.Millisecond)

	// Collect push diagnostics for the scanned file URI.
	var pushItems []types.Diagnostic
	for _, n := range jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics") {
		var params types.PublishDiagnosticsParams
		_ = n.UnmarshalParams(&params)
		if params.URI == fileUri {
			pushItems = params.Diagnostics
		}
	}

	rsp, err := loc.Client.Call(t.Context(), "textDocument/diagnostic", types.DocumentDiagnosticParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: fileUri},
	})
	require.NoError(t, err)

	var result types.RelatedFullDocumentDiagnosticReport
	require.NoError(t, rsp.UnmarshalResult(&result))

	assert.Equal(t, "full", result.Kind)
	require.NotEmpty(t, result.Items, "textDocument/diagnostic must return findings for the scanned file")
	assert.Equal(t, pushItems, result.Items,
		"pull and push must report byte-identical findings")
}
