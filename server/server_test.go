package server

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/diagnostics"
	"github.com/snyk/snyk-ls/util"
)

var (
	ctx          = context.Background()
	notification *jrpc2.Request
	doc          = lsp.TextDocumentItem{
		URI:        code.FakeDiagnosticUri,
		LanguageID: "java",
		Version:    0,
		Text:       "public class AnnotatorTest {\n  public static void delay(long millis) {\n    try {\n      Thread.sleep(millis);\n    } catch (InterruptedException e) {\n      e.printStackTrace();\n    }\n  }\n}",
	}
	docIdentifier = lsp.VersionedTextDocumentIdentifier{
		TextDocumentIdentifier: lsp.TextDocumentIdentifier{URI: doc.URI},
		Version:                doc.Version,
	}
)

func didOpenTextParams() lsp.DidOpenTextDocumentParams {
	// see https://microsoft.github.io/language-server-protocol/specifications/specification-3-17/#documentSelector
	didOpenParams := lsp.DidOpenTextDocumentParams{
		TextDocument: doc,
	}
	return didOpenParams
}

func didSaveTextParams() lsp.DidSaveTextDocumentParams {
	// see https://microsoft.github.io/language-server-protocol/specifications/specification-3-17/#documentSelector
	didSaveParams := lsp.DidSaveTextDocumentParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: doc.URI},
	}
	return didSaveParams
}

func startServer() server.Local {
	var srv *jrpc2.Server

	if environment.RunIntegTest {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		diagnostics.SnykCode = &code.SnykCodeBackendService{}
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		diagnostics.SnykCode = &code.FakeSnykCodeApiService{}
	}

	lspHandlers := handler.Map{
		"initialize":                     InitializeHandler(),
		"textDocument/didOpen":           TextDocumentDidOpenHandler(&srv),
		"textDocument/didChange":         TextDocumentDidChangeHandler(),
		"textDocument/didClose":          TextDocumentDidCloseHandler(),
		"textDocument/didSave":           TextDocumentDidSaveHandler(&srv),
		"textDocument/willSave":          TextDocumentWillSaveHandler(),
		"textDocument/willSaveWaitUntil": TextDocumentWillSaveWaitUntilHandler(),
		"shutdown":                       Shutdown(),
		"exit":                           Exit(&srv),
		"textDocument/codeLens":          TextDocumentCodeLens(),
		// "codeLens/resolve":               codeLensResolve(&server),
	}

	opts := &server.LocalOptions{
		Client: &jrpc2.ClientOptions{
			OnNotify: func(request *jrpc2.Request) {
				notification = request
			},
		},
		Server: &jrpc2.ServerOptions{
			AllowPush: true,
		},
	}
	loc := server.NewLocal(lspHandlers, opts)
	srv = loc.Server
	return loc
}

func Test_serverShouldStart(t *testing.T) {
	loc := startServer()
	// TODO(pavel): extract to setup/teardown methods
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	si := loc.Server.ServerInfo()

	fmt.Println(strings.Join(si.Methods, "\n"))
}

func Test_dummy_shouldNotBeServed(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	_, err := loc.Client.Call(ctx, "dummy", nil)
	if err == nil {
		log.Fatal().Err(err)
	}
}

func Test_initialize_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}
}

func Test_initialize_shouldSupportDocumentOpening(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.OpenClose, true)
}

func Test_initialize_shouldSupportDocumentChanges(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.Change, lsp.TDSKFull)
}

func Test_initialize_shouldSupportDocumentSaving(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.Save, &lsp.SaveOptions{IncludeText: true})
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSave, true)
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSaveWaitUntil, true)
}

func Test_initialize_shouldSupportCodeLens(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}
	assert.Equal(t, result.Capabilities.CodeLensProvider.ResolveProvider, true)
}

func Test_textDocumentDidOpenHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	didOpenParams := didOpenTextParams()

	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	// should receive diagnosticsParams
	diagnosticsParams := lsp.PublishDiagnosticsParams{}

	// wait for publish
	assert.Eventually(t, func() bool { return notification != nil }, 5*time.Second, 10*time.Millisecond)
	_ = notification.UnmarshalParams(&diagnosticsParams)
	assert.Equal(t, didOpenParams.TextDocument.URI, diagnosticsParams.URI)
}

func Test_textDocumentDidChangeHandler_shouldAcceptUri(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	// register our dummy document
	didOpenParams := didOpenTextParams()
	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	didChangeParams := lsp.DidChangeTextDocumentParams{
		TextDocument:   docIdentifier,
		ContentChanges: nil,
	}

	_, err = loc.Client.Call(ctx, "textDocument/didChange", didChangeParams)
	if err != nil {
		log.Fatal().Err(err)
	}
}

func Test_textDocumentDidSaveHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	didSaveParams := didSaveTextParams()

	_, err := loc.Client.Call(ctx, "textDocument/didSave", didSaveParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	// should receive diagnostics
	diags := lsp.PublishDiagnosticsParams{}

	// wait for publish
	assert.Eventually(t, func() bool { return notification != nil }, 5*time.Second, 10*time.Millisecond)
	_ = notification.UnmarshalParams(&diags)
	assert.Equal(t, didSaveParams.TextDocument.URI, diags.URI)
}

func Test_textDocumentWillSaveWaitUntilHandler_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	_, err := loc.Client.Call(ctx, "textDocument/willSaveWaitUntil", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
}

func Test_textDocumentWillSaveHandler_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	_, err := loc.Client.Call(ctx, "textDocument/willSave", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
}

func Test_textDocumentCodeLens_shouldReturnCodeLenses(t *testing.T) {
	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	codeLensParams := lsp.CodeLensParams{
		TextDocument: docIdentifier.TextDocumentIdentifier,
	}

	// populate caches
	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenTextParams())
	if err != nil {
		log.Fatal().Err(err)
	}
	rsp, err := loc.Client.Call(ctx, "textDocument/codeLens", codeLensParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	var codeLenses []lsp.CodeLens
	_ = rsp.UnmarshalResult(&codeLenses)
	if environment.RunIntegTest {
		assert.Equal(t, 2, len(codeLenses))
	} else {
		assert.Equal(t, 1, len(codeLenses))
	}
}

func Test_IntegrationTestBigProjectScan(t *testing.T) {
	if !environment.RunIntegTest {
		t.Skip("set" + environment.INTEG_TESTS + "to run integration tests")
	}

	loc := startServer()
	defer func(loc server.Local) {
		_ = loc.Close()
	}(loc)

	var cloneTargetDir, err = setupTestRepo()
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't setup test repo")
	}

	// register all files
	err = filepath.Walk(cloneTargetDir, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		content, _ := os.ReadFile(path)
		file := lsp.TextDocumentItem{URI: lsp.DocumentURI("file://" + path), Text: string(content)}
		diagnostics.RegisterDocument(file)
		return err
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Error registering files in repo")
	}

	// set real backend
	diagnostics.SnykCode = &code.SnykCodeBackendService{}

	testPath := cloneTargetDir + "/maven-compat/src/test/java/org/apache/maven/repository/legacy/LegacyRepositorySystemTest.java"
	testFileContent, err := os.ReadFile(testPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't read file content of test file")
	}
	didOpenParams := lsp.DidOpenTextDocumentParams{
		TextDocument: lsp.TextDocumentItem{
			URI:  lsp.DocumentURI("file://" + testPath),
			Text: string(testFileContent),
		},
	}
	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err).Msg("Call failed")
	}

	// should receive diagnosticsParams
	diagnosticsParams := lsp.PublishDiagnosticsParams{}

	assert.Eventually(t, func() bool { return notification != nil }, 10*time.Second, 10*time.Millisecond)
	_ = notification.UnmarshalParams(&diagnosticsParams)

	assert.Equal(t, didOpenParams.TextDocument.URI, diagnosticsParams.URI)
	assert.Len(t, diagnosticsParams.Diagnostics, 1)
	assert.Equal(t, diagnosticsParams.Diagnostics[0].Code, diagnostics.GetDiagnostics(diagnosticsParams.URI, util.FileLevel)[0].Code)
	assert.Equal(t, diagnosticsParams.Diagnostics[0].Range, diagnostics.GetDiagnostics(diagnosticsParams.URI, util.FileLevel)[0].Range)
}

func setupTestRepo() (string, error) {
	// clone to temp dir - specific version for reproducible test results
	cloneTargetDir, _ := os.MkdirTemp(os.TempDir(), "integ_test_repo_*")
	clone := exec.Command("git", "clone", "https://github.com/apache/maven", cloneTargetDir)
	reset := exec.Command("git", "reset", "--hard", "18725ec1e")
	reset.Dir = cloneTargetDir
	clean := exec.Command("git", "clean", "--force")
	clean.Dir = cloneTargetDir

	output, err := clone.CombinedOutput()
	if err != nil {
		log.Fatal().Err(err)
	}
	log.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()
	log.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()
	log.Debug().Msg(string(output))
	return cloneTargetDir, err
}
