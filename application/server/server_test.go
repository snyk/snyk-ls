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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

const maxIntegTestDuration = 15 * time.Minute

var (
	ctx             = context.Background()
	jsonRPCRecorder = testutil.JsonRPCRecorder{}
)

func didOpenTextParams() (sglsp.DidOpenTextDocumentParams, string, func()) {
	diagnosticUri, path := code.FakeDiagnosticUri()
	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{URI: uri.PathToUri(diagnosticUri)},
	}
	return didOpenParams, path, func() {
		os.RemoveAll(path)
	}
}

func setupServer(t *testing.T) server.Local {
	testutil.UnitTest(t)
	di.TestInit(t)
	cleanupChannels()
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	workspace.Set(workspace.New(performance.NewTestInstrumentor()))
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
	di.HoverService().ClearAllHovers()
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
		t.Fatal(t, err, "call succeeded")
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

func Test_initialize_containsServerInfo(t *testing.T) {
	loc := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}
	assert.Equal(t, config.LsProtocolVersion, result.ServerInfo.Version)
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

func Test_initialize_updatesSettings(t *testing.T) {
	loc := setupServer(t)

	clientParams := lsp.InitializeParams{
		InitializationOptions: lsp.Settings{Organization: "fancy org"},
	}

	rsp, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}
	assert.Equal(t, "fancy org", config.CurrentConfig().GetOrganization())
}

func Test_textDocumentDidOpenHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	_, _ = loc.Client.Call(ctx, "initialize", nil)
	didOpenParams, dir, cleanup := didOpenTextParams()
	defer cleanup()
	workspace.Get().AddFolder(workspace.NewFolder(dir, "test", di.Scanner(), di.HoverService()))

	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	// wait for publish
	assert.Eventually(
		t,
		checkForPublishedDiagnostics(workspace.Get(), uri.PathFromUri(didOpenParams.TextDocument.URI), -1),
		2*time.Second,
		10*time.Millisecond,
	)
}

func Test_textDocumentDidOpenHandler_shouldDownloadCLI(t *testing.T) {
	loc := setupServer(t)
	testutil.IntegTest(t)

	testutil.CreateDummyProgressListener(t)

	// remove cli for testing
	installer := install.NewInstaller(error_reporting.NewTestErrorReporter())
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
	err := os.Unsetenv("SNYK_CLI_PATH")
	if err != nil {
		t.Fatal("couldn't unset environment")
	}
	c := config.New()
	c.SetToken(testutil.GetEnvironmentToken())
	config.SetCurrentConfig(c)

	didOpenParams, dir, cleanup := didOpenTextParams()
	defer cleanup()

	workspace.Get().AddFolder(workspace.NewFolder(dir, "test", di.Scanner(), di.HoverService()))

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	assert.Eventually(t, func() bool {
		find, _ := installer.Find()
		return find != ""
	}, maxIntegTestDuration, 10*time.Millisecond)
}

func Test_textDocumentDidChangeHandler_shouldAcceptUri(t *testing.T) {
	loc := setupServer(t)

	// register our dummy document
	didOpenParams, dir, cleanup := didOpenTextParams()
	defer cleanup()

	workspace.Get().AddFolder(workspace.NewFolder(dir, "test", di.Scanner(), di.HoverService()))

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
	loc := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	_, _ = loc.Client.Call(ctx, "initialize", nil)
	diagnosticUri, tempDir := code.FakeDiagnosticUri()
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(diagnosticUri)},
	}
	defer os.RemoveAll(tempDir)
	workspace.Get().AddFolder(workspace.NewFolder(tempDir, "Test", di.Scanner(), di.HoverService()))

	_, err := loc.Client.Call(ctx, "textDocument/didSave", didSaveParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	// wait for publish
	assert.Eventually(
		t,
		checkForPublishedDiagnostics(workspace.Get(), uri.PathFromUri(didSaveParams.TextDocument.URI), -1),
		2*time.Second,
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
	loc := setupServer(t)
	testutil.IntegTest(t)
	testutil.CreateDummyProgressListener(t)
	file := testutil.CreateTempFile(t.TempDir(), t)
	w := workspace.Get()

	f := lsp.WorkspaceFolder{Name: filepath.Dir(file.Name()), Uri: uri.PathToUri(file.Name())}
	_, err := loc.Client.Call(ctx, "workspace/didChangeWorkspaceFolders", lsp.DidChangeWorkspaceFoldersParams{
		Event: lsp.WorkspaceFoldersChangeEvent{
			Added: []lsp.WorkspaceFolder{f},
		},
	})
	if err != nil {
		t.Fatal(t, err, "error calling server")
	}

	assert.Eventually(t, func() bool {
		folder := w.GetFolderContaining(uri.PathFromUri(f.Uri))
		return folder != nil && folder.IsScanned()
	}, 120*time.Second, time.Millisecond)

	_, err = loc.Client.Call(ctx, "workspace/didChangeWorkspaceFolders", lsp.DidChangeWorkspaceFoldersParams{
		Event: lsp.WorkspaceFoldersChangeEvent{
			Removed: []lsp.WorkspaceFolder{f},
		},
	})
	if err != nil {
		t.Fatal(t, err, "error calling server")
	}

	assert.Nil(t, w.GetFolderContaining(uri.PathFromUri(f.Uri)))
}

func Test_SmokeWorkspaceScanOssAndCode(t *testing.T) {
	ossFile := "package.json"
	codeFile := "app.js"
	runSmokeTest("https://github.com/snyk-labs/nodejs-goof", "0336589", ossFile, codeFile, t)
}

func Test_SmokeWorkspaceScanIacAndCode(t *testing.T) {
	iacFile := "main.tf"
	codeFile := "app.js"
	runSmokeTest("https://github.com/deepcodeg/snykcon-goof.git", "eba8407", iacFile, codeFile, t)
}

func Test_SmokeWorkspaceScanWithTwoUploadBatches(t *testing.T) {
	ossFile := ""
	codeFile := "maven-compat/src/test/java/org/apache/maven/repository/legacy/LegacyRepositorySystemTest.java"
	runSmokeTest("https://github.com/apache/maven", "18725ec1e", ossFile, codeFile, t)
}

func runSmokeTest(repo string, commit string, file1 string, file2 string, t *testing.T) {
	loc := setupServer(t)
	testutil.SmokeTest(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	config.CurrentConfig().SetSnykIacEnabled(true)
	config.CurrentConfig().SetSnykOssEnabled(true)
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	di.Init()

	var cloneTargetDir, err = setupCustomTestRepo(repo, commit)
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't setup test repo")
	}
	folder := lsp.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}

	clientParams := lsp.InitializeParams{
		WorkspaceFolders: []lsp.WorkspaceFolder{folder},
	}

	_, err = loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(t, err, "Initialization failed")
	}

	var testPath string
	if file1 != "" {
		testPath = filepath.Join(cloneTargetDir, file1)
		textDocumentDidOpen(&loc, testPath)
		// serve diagnostics from file scan
		assert.Eventually(t, checkForPublishedDiagnostics(workspace.Get(), testPath, -1), maxIntegTestDuration, 10*time.Millisecond)
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		f := workspace.Get().GetFolderContaining(cloneTargetDir)
		return f != nil && f.IsScanned()
	}, maxIntegTestDuration, 2*time.Millisecond)

	testPath = filepath.Join(cloneTargetDir, file2)
	textDocumentDidOpen(&loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(workspace.Get(), testPath, -1), maxIntegTestDuration, 10*time.Millisecond)
}

// Check if published diagnostics for given testPath match the expectedNumber.
// If expectedNumber == -1 assume check for expectedNumber > 0
func checkForPublishedDiagnostics(w *workspace.Workspace, testPath string, expectedNumber int) func() bool {
	return func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
		if len(notifications) < 1 {
			return false
		}
		for _, n := range notifications {
			diagnosticsParams := lsp.PublishDiagnosticsParams{}
			_ = n.UnmarshalParams(&diagnosticsParams)
			if diagnosticsParams.URI == uri.PathToUri(testPath) {
				f := w.GetFolderContaining(testPath)
				hasExpectedDiagnostics := f != nil && (expectedNumber == -1 && len(diagnosticsParams.Diagnostics) > 0) || (len(diagnosticsParams.Diagnostics) == expectedNumber)
				if hasExpectedDiagnostics {
					return hasExpectedDiagnostics
				}
			}
		}
		return false
	}
}

func Test_IntegrationHoverResults(t *testing.T) {
	loc := setupServer(t)
	testutil.IntegTest(t)

	var cloneTargetDir, err = setupCustomTestRepo("https://github.com/snyk-labs/nodejs-goof", "0336589")
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't setup test repo")
	}
	folder := lsp.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}
	clientParams := lsp.InitializeParams{
		WorkspaceFolders: []lsp.WorkspaceFolder{folder},
	}

	_, err = loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(t, err, "Initialization failed")
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		w := workspace.Get()
		f := w.GetFolderContaining(cloneTargetDir)
		return f != nil && f.IsScanned()
	}, maxIntegTestDuration, 100*time.Millisecond)

	testPath := cloneTargetDir + string(os.PathSeparator) + "package.json"
	testPosition := sglsp.Position{
		Line:      17,
		Character: 7,
	}

	hoverResp, err := loc.Client.Call(ctx, "textDocument/hover", hover.Params{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(testPath)},
		Position:     testPosition,
	})

	if err != nil {
		t.Fatal(t, err, "Hover retrieval failed")
	}

	hoverResult := hover.Result{}
	err = hoverResp.UnmarshalResult(&hoverResult)
	if err != nil {
		t.Fatal(t, err, "Hover retrieval failed")
	}

	assert.Equal(t, hoverResult.Contents.Value, di.HoverService().GetHover(uri.PathToUri(testPath), testPosition).Contents.Value)
	assert.Equal(t, hoverResult.Contents.Kind, "markdown")
}
func Test_SmokeSnykCodeFileScan(t *testing.T) {
	loc := setupServer(t)
	testutil.SmokeTest(t)
	di.Init()
	config.CurrentConfig().SetSnykCodeEnabled(true)
	_, _ = loc.Client.Call(ctx, "initialize", nil)

	var cloneTargetDir, err = setupCustomTestRepo("https://github.com/snyk-labs/nodejs-goof", "0336589")
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't setup test repo")
	}

	testPath := filepath.Join(cloneTargetDir, "app.js")

	w := workspace.Get()
	f := workspace.NewFolder(cloneTargetDir, "Test", di.Scanner(), di.HoverService())
	w.AddFolder(f)

	_ = textDocumentDidOpen(&loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(w, testPath, 6), maxIntegTestDuration, 10*time.Millisecond)
}

func textDocumentDidOpen(loc *server.Local, testPath string) sglsp.DidOpenTextDocumentParams {
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
