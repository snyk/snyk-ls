package server

import (
	"context"
	"fmt"
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
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/diagnostics"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/cli/install"
	"github.com/snyk/snyk-ls/internal/hover"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	ctx                 = context.Background()
	notificationMessage *jrpc2.Request
	callbackMessage     *jrpc2.Request
)

func didOpenTextParams() (sglsp.DidOpenTextDocumentParams, func()) {
	// see https://microsoft.github.io/language-server-protocol/specifications/specification-3-17/#documentSelector
	diagnosticUri, path := code.FakeDiagnosticUri()
	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{URI: diagnosticUri},
	}
	return didOpenParams, func() {
		os.RemoveAll(path)
	}
}

func didSaveTextParams() (sglsp.DidSaveTextDocumentParams, func()) {
	// see https://microsoft.github.io/language-server-protocol/specifications/specification-3-17/#documentSelector
	diagnosticUri, path := code.FakeDiagnosticUri()
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: diagnosticUri},
	}
	return didSaveParams, func() {
		os.RemoveAll(path)
	}
}

func setupServer() (localServer server.Local, teardown func(l *server.Local)) {
	loc := startServer()
	notificationMessage = nil
	callbackMessage = nil

	return loc, func(loc *server.Local) {
		err := loc.Close()
		if err != nil {
			log.Fatal().Err(err).Msg("Error when closing down server")
		}
		notificationMessage = nil
	}
}

func startServer() server.Local {
	var srv *jrpc2.Server

	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	diagnostics.SnykCode = &code.FakeSnykCodeApiService{}

	lspHandlers := handler.Map{
		"initialize":                          InitializeHandler(&srv),
		"textDocument/didOpen":                TextDocumentDidOpenHandler(&srv),
		"textDocument/didChange":              TextDocumentDidChangeHandler(),
		"textDocument/didClose":               TextDocumentDidCloseHandler(),
		"textDocument/didSave":                TextDocumentDidSaveHandler(&srv),
		"textDocument/willSave":               TextDocumentWillSaveHandler(),
		"textDocument/willSaveWaitUntil":      TextDocumentWillSaveWaitUntilHandler(),
		"shutdown":                            Shutdown(),
		"exit":                                Exit(&srv),
		"workspace/didChangeWorkspaceFolders": WorkspaceDidChangeWorkspaceFoldersHandler(),
		"textDocument/hover":                  TextDocumentHover(),
		"workspace/didChangeConfiguration":    WorkspaceDidChangeConfiguration(),
		"window/workDoneProgress/cancel":      WindowWorkDoneProgressCancelHandler(),
		// "codeLens/resolve":               codeLensResolve(&server),
	}

	opts := &server.LocalOptions{
		Client: &jrpc2.ClientOptions{
			OnNotify: func(request *jrpc2.Request) {
				notificationMessage = request
			},
			OnCallback: func(ctx context.Context, request *jrpc2.Request) (interface{}, error) {
				callbackMessage = request
				return callbackMessage, nil
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
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	si := loc.Server.ServerInfo()

	fmt.Println(strings.Join(si.Methods, "\n"))
}

func Test_dummy_shouldNotBeServed(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	_, err := loc.Client.Call(ctx, "dummy", nil)
	if err == nil {
		log.Fatal().Err(err).Msg("call succeeded")
	}
}

func Test_initialize_shouldBeServed(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

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
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

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
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.Change, sglsp.TDSKFull)
}

func Test_initialize_shouldSupportDocumentSaving(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.Save, &sglsp.SaveOptions{IncludeText: true})
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSave, true)
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSaveWaitUntil, true)
}

func Test_textDocumentDidOpenHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	cli.CurrentSettings = cli.Settings{}
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	didOpenParams, cleanup := didOpenTextParams()
	defer cleanup()

	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	// should receive diagnosticsParams
	diagnosticsParams := lsp.PublishDiagnosticsParams{}

	// wait for publish
	assert.Eventually(t, func() bool { return notification != nil }, 5*time.Second, 10*time.Millisecond)
	if notificationMessage != nil {
		_ = notificationMessage.UnmarshalParams(&diagnosticsParams)
		assert.Equal(t, didOpenParams.TextDocument.URI, diagnosticsParams.URI)
	}
}

func Test_textDocumentDidOpenHandler_shouldDownloadCLI(t *testing.T) {
	testutil.IntegTest(t)
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	// remove cli for testing
	install.Mutex.Lock()
	installer := install.NewInstaller()
	for {
		find, err := installer.Find()
		if err == nil {
			err = os.Remove(find)
			log.Debug().Msgf("Test: removing cli at %s", find)
			if err != nil {
				t.Fatal("couldn't remove cli for test")
			}
		} else {
			break
		}
	}
	install.Mutex.Unlock()
	err := os.Unsetenv("SNYK_CLI_PATH")
	if err != nil {
		t.Fatal("couldn't unset environment")
	}
	environment.Load()
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	cli.CurrentSettings = cli.Settings{}

	didOpenParams, cleanup := didOpenTextParams()
	defer cleanup()

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	assert.Eventually(t, func() bool {
		find, _ := installer.Find()
		return find != ""
	}, 120*time.Second, 10*time.Millisecond)
}

func Test_textDocumentDidChangeHandler_shouldAcceptUri(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	// register our dummy document
	didOpenParams, cleanup := didOpenTextParams()
	defer cleanup()

	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	didChangeParams := sglsp.DidChangeTextDocumentParams{
		TextDocument: sglsp.VersionedTextDocumentIdentifier{
			TextDocumentIdentifier: sglsp.TextDocumentIdentifier{URI: didOpenParams.TextDocument.URI},
			Version:                0,
		},
		ContentChanges: nil,
	}

	_, err = loc.Client.Call(ctx, "textDocument/didChange", didChangeParams)
	if err != nil {
		log.Fatal().Err(err)
	}
}

func Test_textDocumentDidSaveHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	cli.CurrentSettings = cli.Settings{}
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	didSaveParams, cleanup := didSaveTextParams()
	defer cleanup()

	_, err := loc.Client.Call(ctx, "textDocument/didSave", didSaveParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	// should receive diagnostics

	// wait for publish
	assert.Eventually(t, func() bool { return notificationMessage != nil }, 5*time.Second, 10*time.Millisecond)
	if !t.Failed() {
		diags := lsp.PublishDiagnosticsParams{}
		_ = notificationMessage.UnmarshalParams(&diags)
		assert.Equal(t, didSaveParams.TextDocument.URI, diags.URI)
	}
}

func Test_textDocumentWillSaveWaitUntilHandler_shouldBeServed(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	_, err := loc.Client.Call(ctx, "textDocument/willSaveWaitUntil", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
}

func Test_textDocumentWillSaveHandler_shouldBeServed(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	_, err := loc.Client.Call(ctx, "textDocument/willSave", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
}

func Test_workspaceDidChangeWorkspaceFolders_shouldProcessChanges(t *testing.T) {
	testutil.IntegTest(t)
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	folder := lsp.WorkspaceFolder{Name: "test1", Uri: sglsp.DocumentURI("test1")}
	_, err := loc.Client.Call(ctx, "workspace/didChangeWorkspaceFolders", lsp.DidChangeWorkspaceFoldersParams{
		Event: lsp.WorkspaceFoldersChangeEvent{
			Added: []lsp.WorkspaceFolder{folder},
		},
	})
	if err != nil {
		log.Fatal().Err(err).Msg("error calling server")
	}

	assert.True(t, diagnostics.IsWorkspaceFolderScanned(folder))

	_, err = loc.Client.Call(ctx, "workspace/didChangeWorkspaceFolders", lsp.DidChangeWorkspaceFoldersParams{
		Event: lsp.WorkspaceFoldersChangeEvent{
			Removed: []lsp.WorkspaceFolder{folder},
		},
	})
	if err != nil {
		log.Fatal().Err(err).Msg("error calling server")
	}

	assert.False(t, diagnostics.IsWorkspaceFolderScanned(folder))
}

func Test_IntegrationWorkspaceScanOssAndCode(t *testing.T) {
	testutil.IntegTest(t)
	ossFile := "package.json"
	codeFile := "app.js"
	runIntegrationTest("https://github.com/snyk/goof", "0336589", ossFile, codeFile, t)
}

func Test_IntegrationWorkspaceScanIacAndCode(t *testing.T) {
	testutil.IntegTest(t)
	iacFile := "main.tf"
	codeFile := "app.js"
	runIntegrationTest("https://github.com/deepcodeg/snykcon-goof.git", "eba8407", iacFile, codeFile, t)
}

func Test_IntegrationWorkspaceScanMaven(t *testing.T) {
	testutil.IntegTest(t)
	ossFile := ""
	codeFile := "maven-compat/src/test/java/org/apache/maven/repository/legacy/LegacyRepositorySystemTest.java"
	runIntegrationTest("https://github.com/apache/maven", "18725ec1e", ossFile, codeFile, t)
}

func runIntegrationTest(repo string, commit string, file1 string, file2 string, t *testing.T) {
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	cli.CurrentSettings = cli.Settings{}
	diagnostics.ClearWorkspaceFolderScanned()
	diagnostics.ClearEntireDiagnosticsCache()
	diagnostics.ClearRegisteredDocuments()
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	var cloneTargetDir, err = setupCustomTestRepo(repo, commit)
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't setup test repo")
	}
	folder := lsp.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  sglsp.DocumentURI("file:" + cloneTargetDir),
	}
	clientParams := lsp.InitializeParams{
		WorkspaceFolders: []lsp.WorkspaceFolder{folder},
	}

	_, err = loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		log.Fatal().Err(err).Msg("Initialization failed")
	}

	var testPath string
	if file1 != "" {
		testPath = filepath.Join(cloneTargetDir, file1)
		textDocumentDidOpen(&loc, testPath)
		// serve diagnostics from file scan
		assert.Eventually(t, func() bool {
			return notificationMessage != nil && len(diagnostics.DocumentDiagnosticsFromCache(uri.PathToUri(testPath))) > 0
		}, 5*time.Second, 2*time.Millisecond)
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		return diagnostics.IsWorkspaceFolderScanned(folder)
	}, 600*time.Second, 100*time.Millisecond)

	testPath = filepath.Join(cloneTargetDir, file2)
	textDocumentDidOpen(&loc, testPath)

	// serve diagnostics from workspace & file scan
	assert.Eventually(t, func() bool {
		return notificationMessage != nil && len(diagnostics.DocumentDiagnosticsFromCache(uri.PathToUri(testPath))) > 0
	}, 5*time.Second, 2*time.Millisecond)
}

func Test_IntegrationHoverResults(t *testing.T) {
	testutil.IntegTest(t)
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	cli.CurrentSettings = cli.Settings{}
	diagnostics.ClearEntireDiagnosticsCache()
	diagnostics.ClearRegisteredDocuments()
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	var cloneTargetDir, err = setupCustomTestRepo("https://github.com/snyk/goof", "0336589")
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't setup test repo")
	}
	folder := lsp.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  sglsp.DocumentURI("file:" + cloneTargetDir),
	}
	clientParams := lsp.InitializeParams{
		WorkspaceFolders: []lsp.WorkspaceFolder{folder},
	}

	_, err = loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		log.Fatal().Err(err).Msg("Initialization failed")
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
			return notificationMessage != nil && len(diagnostics.DocumentDiagnosticsFromCache(uri.PathToUri(testPath))) > 0
		}, 5*time.Second, 2*time.Millisecond)

	testPath := cloneTargetDir + string(os.PathSeparator) + "package.json"
	testPosition := sglsp.Position{
		Line:      17,
		Character: 7,
	}

	hoverResp, err := loc.Client.Call(ctx, "textDocument/hover", lsp.HoverParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(testPath)},
		Position:     testPosition,
	})

	if err != nil {
		log.Fatal().Err(err).Msg("Hover retrieval failed")
	}

	hoverResult := lsp.HoverResult{}
	err = hoverResp.UnmarshalResult(&hoverResult)
	if err != nil {
		log.Fatal().Err(err).Msg("Hover retrieval failed")
	}

	assert.Equal(t, hoverResult.Contents.Value, hover.GetHover(uri.PathToUri(testPath), testPosition).Contents.Value)
	assert.Equal(t, hoverResult.Contents.Kind, "markdown")
}

func Test_IntegrationFileScan(t *testing.T) {
	testutil.IntegTest(t)
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	cli.CurrentSettings = cli.Settings{}
	diagnostics.ClearEntireDiagnosticsCache()
	diagnostics.ClearRegisteredDocuments()
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	var cloneTargetDir, err = setupCustomTestRepo("https://github.com/snyk/goof", "0336589")
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't setup test repo")
	}

	testPath := cloneTargetDir + string(os.PathSeparator) + "app.js"
	didOpenParams, diagnosticsParams := textDocumentDidOpen(&loc, testPath)

	assert.Eventually(t, func() bool { return notificationMessage != nil }, 10*time.Second, 10*time.Millisecond)
	_ = notificationMessage.UnmarshalParams(&diagnosticsParams)

	assert.Equal(t, didOpenParams.TextDocument.URI, diagnosticsParams.URI)
	assert.Len(t, diagnosticsParams.Diagnostics, 6)
	assert.Equal(t, diagnosticsParams.Diagnostics[0].Code, diagnostics.GetDiagnostics(diagnosticsParams.URI)[0].Code)
	assert.Equal(t, diagnosticsParams.Diagnostics[0].Range, diagnostics.GetDiagnostics(diagnosticsParams.URI)[0].Range)
}

func textDocumentDidOpen(loc *server.Local, testPath string) (sglsp.DidOpenTextDocumentParams, lsp.PublishDiagnosticsParams) {
	diagnostics.SnykCode = &code.SnykCodeBackendService{}
	// should receive diagnosticsParams

	testFileContent, err := os.ReadFile(testPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't read file content of test file")
	}

	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{
			URI:  uri.PathToUri(testPath),
			Text: string(testFileContent),
		},
	}

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err).Msg("Call failed")
	}

	diagnosticsParams := lsp.PublishDiagnosticsParams{}
	return didOpenParams, diagnosticsParams
}

func setupCustomTestRepo(url string, targetCommit string) (string, error) {
	// clone to temp dir - specific version for reproducible test results
	cloneTargetDir, err := os.MkdirTemp(os.TempDir(), "integ_test_repo_")
	if err != nil {
		log.Fatal().Err(err).Msg("couldn't create temp dir")
	}
	cmd := []string{"clone", url, cloneTargetDir}
	log.Debug().Interface("cmd", cmd).Msg("clone command")
	clone := exec.Command("git", cmd...)
	reset := exec.Command("git", "reset", "--hard", targetCommit)
	reset.Dir = cloneTargetDir

	clean := exec.Command("git", "clean", "--force")
	clean.Dir = cloneTargetDir

	output, err := clone.CombinedOutput()
	if err != nil {
		log.Fatal().Err(err).Msg("clone didn't work")
	}

	log.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	log.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	log.Debug().Msg(string(output))
	return cloneTargetDir, err
}
