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

	"github.com/creachadair/jrpc2/handler"

	"github.com/snyk/snyk-ls/di"

	"github.com/creachadair/jrpc2"
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
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	ctx             = context.Background()
	jsonRPCRecorder = testutil.JsonRPCRecorder{}
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

func setupServer(t *testing.T) server.Local {
	di.TestInit()
	diagnostics.ClearEntireDiagnosticsCache()
	diagnostics.ClearWorkspaceFolderScanned()
	cleanupChannels()
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	loc := startServer()

	t.Cleanup(func() {
		err := loc.Close()
		if err != nil {
			log.Error().Err(err).Msg("Error when closing down server")
		}
		cleanupChannels()
		jsonRPCRecorder.ClearCallbacks()
		jsonRPCRecorder.ClearNotifications()
	})
	return loc
}

func cleanupChannels() {
	notification.DisposeListener()
	disposeProgressListener()
	hover.ClearAllHovers()
}

func startServer() server.Local {
	var srv *jrpc2.Server

	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	opts := &server.LocalOptions{
		Client: &jrpc2.ClientOptions{
			OnNotify: func(request *jrpc2.Request) {
				jsonRPCRecorder.Record(*request)
			},
			OnCallback: func(ctx context.Context, request *jrpc2.Request) (interface{}, error) {
				jsonRPCRecorder.Record(*request)
				return *request, nil
			},
		},
		Server: &jrpc2.ServerOptions{
			AllowPush: true,
		},
	}

	handlers := &handler.Map{}
	loc := server.NewLocal(handlers, opts)
	srv = loc.Server
	initHandlers(srv, handlers)

	return loc
}

func Test_serverShouldStart(t *testing.T) {
	loc := setupServer(t)

	si := loc.Server.ServerInfo()

	fmt.Println(strings.Join(si.Methods, "\n"))
}

func Test_dummy_shouldNotBeServed(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "dummy", nil)
	if err == nil {
		log.Fatal().Err(err).Msg("call succeeded")
	}
}

func Test_initialize_shouldBeServed(t *testing.T) {
	loc := setupServer(t)

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
	loc := setupServer(t)

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

func Test_initialize_shouldSupportDocumentSaving(t *testing.T) {
	loc := setupServer(t)

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
	environment.CurrentEnabledProducts.Code.Set(true)
	cli.CurrentSettings = cli.Settings{}
	loc := setupServer(t)

	didOpenParams, cleanup := didOpenTextParams()
	defer cleanup()

	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	// wait for publish
	assert.Eventually(
		t,
		checkForPublishedDiagnostics(uri.PathFromUri(didOpenParams.TextDocument.URI), -1),
		120*time.Second,
		10*time.Millisecond,
	)
}

func Test_textDocumentDidOpenHandler_shouldDownloadCLI(t *testing.T) {
	testutil.IntegTest(t)
	loc := setupServer(t)

	testutil.CreateDummyProgressListener(t)

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
	environment.EnabledProductsFromEnv()
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
	loc := setupServer(t)

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
	environment.EnabledProductsFromEnv()
	cli.CurrentSettings = cli.Settings{}
	loc := setupServer(t)

	didSaveParams, cleanup := didSaveTextParams()
	defer cleanup()

	_, err := loc.Client.Call(ctx, "textDocument/didSave", didSaveParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	// wait for publish
	assert.Eventually(
		t,
		checkForPublishedDiagnostics(uri.PathFromUri(didSaveParams.TextDocument.URI), -1),
		120*time.Second,
		10*time.Millisecond,
	)
}

func Test_textDocumentWillSaveWaitUntilHandler_shouldBeServed(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "textDocument/willSaveWaitUntil", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
}

func Test_textDocumentWillSaveHandler_shouldBeServed(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "textDocument/willSave", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
}

func Test_workspaceDidChangeWorkspaceFolders_shouldProcessChanges(t *testing.T) {
	testutil.IntegTest(t)
	loc := setupServer(t)
	testutil.CreateDummyProgressListener(t)

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
	environment.CurrentEnabledProducts.Code.Set(true)
	environment.CurrentEnabledProducts.OpenSource.Set(true)
	environment.CurrentEnabledProducts.Iac.Set(true)
	cli.CurrentSettings = cli.Settings{}
	diagnostics.ClearWorkspaceFolderScanned()
	diagnostics.ClearEntireDiagnosticsCache()
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	loc := setupServer(t)
	di.Init()

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
		assert.Eventually(t, checkForPublishedDiagnostics(testPath, -1), 120*time.Second, 10*time.Millisecond)
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		return diagnostics.IsWorkspaceFolderScanned(folder)
	}, 600*time.Second, 2*time.Millisecond)

	testPath = filepath.Join(cloneTargetDir, file2)
	textDocumentDidOpen(&loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(testPath, -1), 120*time.Second, 10*time.Millisecond)
}

// Check if published diagnostics for given testPath match the expectedNumber.
// If expectedNumber == -1 assume check for expectedNumber > 0
func checkForPublishedDiagnostics(testPath string, expectedNumber int) func() bool {
	return func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
		if len(notifications) < 1 {
			return false
		}
		for _, n := range notifications {
			diagnosticsParams := lsp.PublishDiagnosticsParams{}
			_ = n.UnmarshalParams(&diagnosticsParams)
			if diagnosticsParams.URI == uri.PathToUri(testPath) {
				if expectedNumber == -1 {
					return len(diagnostics.DocumentDiagnosticsFromCache(diagnosticsParams.URI)) > 0
				} else {
					return len(diagnostics.DocumentDiagnosticsFromCache(diagnosticsParams.URI)) == expectedNumber
				}
			}
		}
		return false
	}
}

func Test_IntegrationHoverResults(t *testing.T) {
	testutil.IntegTest(t)
	environment.EnabledProductsFromEnv()
	cli.CurrentSettings = cli.Settings{}
	diagnostics.ClearEntireDiagnosticsCache()
	loc := setupServer(t)

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
		return diagnostics.IsWorkspaceFolderScanned(folder)
	}, 600*time.Second, 100*time.Millisecond)

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
	environment.EnabledProductsFromEnv()
	cli.CurrentSettings = cli.Settings{}
	diagnostics.ClearEntireDiagnosticsCache()
	loc := setupServer(t)
	di.Init()

	var cloneTargetDir, err = setupCustomTestRepo("https://github.com/snyk/goof", "0336589")
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't setup test repo")
	}

	testPath := filepath.Join(cloneTargetDir, "app.js")
	_ = textDocumentDidOpen(&loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(testPath, 6), 120*time.Second, 10*time.Millisecond)
}

func textDocumentDidOpen(loc *server.Local, testPath string) sglsp.DidOpenTextDocumentParams {
	di.Init()
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

	return didOpenParams
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
