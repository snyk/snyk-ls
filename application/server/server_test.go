package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adrg/xdg"
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

func didOpenTextParams(t *testing.T) (sglsp.DidOpenTextDocumentParams, string) {
	filePath, dirPath := code.FakeDiagnosticPath(t)
	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{URI: uri.PathToUri(filePath)},
	}
	t.Cleanup(func() {
		os.RemoveAll(dirPath)
	})
	return didOpenParams, dirPath
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
		t.Fatal(err, "call succeeded")
	}
}

func Test_initialize_shouldBeServed(t *testing.T) {
	loc := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
}

func Test_initialize_containsServerInfo(t *testing.T) {
	loc := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, config.LsProtocolVersion, result.ServerInfo.Version)
}

func Test_initialize_shouldSupportDocumentOpening(t *testing.T) {
	loc := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.OpenClose, true)
}

func Test_initialize_shouldSupportDocumentSaving(t *testing.T) {
	loc := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.Save, &sglsp.SaveOptions{IncludeText: true})
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSave, true)
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSaveWaitUntil, true)
}

func Test_initialize_shouldSupportCodeLenses(t *testing.T) {
	loc := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result.Capabilities.CodeLensProvider.ResolveProvider, false)
}

func Test_TextDocumentCodeLenses_shouldReturnCodeLenses(t *testing.T) {
	loc := setupServer(t)

	didOpenParams, dir := didOpenTextParams(t)

	clientParams := lsp.InitializeParams{
		RootURI: uri.PathToUri(dir),
		InitializationOptions: lsp.Settings{
			ActivateSnykCode:            "true",
			ActivateSnykOpenSource:      "false",
			ActivateSnykIac:             "false",
			Organization:                "fancy org",
			Token:                       "xxx",
			ManageBinariesAutomatically: "false",
			CliPath:                     "dummy",
		},
	}
	_, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "couldn't initialize")
	}

	// wait for publish
	assert.Eventually(
		t,
		func() bool {
			path := uri.PathFromUri(didOpenParams.TextDocument.URI)
			return workspace.Get().GetFolderContaining(path).DocumentDiagnosticsFromCache(path) != nil
		},
		5*time.Second,
		time.Millisecond,
		"Couldn't get diagnostics from cache",
	)

	rsp, _ := loc.Client.Call(ctx, "textDocument/codeLens", sglsp.CodeLensParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: didOpenParams.TextDocument.URI,
		},
	})

	var lenses []sglsp.CodeLens
	if err := rsp.UnmarshalResult(&lenses); err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, lenses)
	assert.Len(t, lenses, 1)
	assert.Equal(t, lenses[0].Command.Command, code.FakeCommand.Command)
}

func Test_initialize_updatesSettings(t *testing.T) {
	loc := setupServer(t)

	clientParams := lsp.InitializeParams{
		InitializationOptions: lsp.Settings{Organization: "fancy org", Token: "xxx"},
	}

	rsp, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "fancy org", config.CurrentConfig().GetOrganization())
	assert.Equal(t, "xxx", config.CurrentConfig().Token())
}

func Test_textDocumentDidOpenHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := setupServer(t)
	didOpenParams, dir := didOpenTextParams(t)

	clientParams := lsp.InitializeParams{
		RootURI: uri.PathToUri(dir),
		InitializationOptions: lsp.Settings{
			ActivateSnykCode:            "true",
			ActivateSnykOpenSource:      "false",
			ActivateSnykIac:             "false",
			Organization:                "fancy org",
			Token:                       "xxx",
			ManageBinariesAutomatically: "false",
			CliPath:                     "dummy",
		},
	}
	_, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "couldn't initialize")
	}

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		t.Fatal(err)
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

	didOpenParams, dir := didOpenTextParams(t)

	workspace.Get().AddFolder(workspace.NewFolder(dir, "test", di.Scanner(), di.HoverService()))

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		t.Fatal(err)
	}

	assert.Eventually(t, func() bool {
		find, _ := installer.Find()
		return find != ""
	}, maxIntegTestDuration, 10*time.Millisecond)
}

func Test_textDocumentDidChangeHandler_shouldAcceptUri(t *testing.T) {
	loc := setupServer(t)

	// register our dummy document
	didOpenParams, dir := didOpenTextParams(t)

	workspace.Get().AddFolder(workspace.NewFolder(dir, "test", di.Scanner(), di.HoverService()))

	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
}

func Test_textDocumentDidSaveHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	_, _ = loc.Client.Call(ctx, "initialize", nil)
	diagnosticUri, tempDir := code.FakeDiagnosticPath(t)
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(diagnosticUri)},
	}
	defer os.RemoveAll(tempDir)
	workspace.Get().AddFolder(workspace.NewFolder(tempDir, "Test", di.Scanner(), di.HoverService()))

	_, err := loc.Client.Call(ctx, "textDocument/didSave", didSaveParams)
	if err != nil {
		t.Fatal(err)
	}

	// wait for publish
	assert.Eventually(
		t,
		checkForPublishedDiagnostics(workspace.Get(), uri.PathFromUri(didSaveParams.TextDocument.URI), -1),
		60*time.Second,
		500*time.Millisecond,
	)
}

func Test_textDocumentWillSaveWaitUntilHandler_shouldBeServed(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "textDocument/willSaveWaitUntil", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_textDocumentWillSaveHandler_shouldBeServed(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "textDocument/willSave", nil)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err, "error calling server")
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
		t.Fatal(err, "error calling server")
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

	var cloneTargetDir, err = setupCustomTestRepo(repo, commit, t)
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
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
		t.Fatal(err, "Initialization failed")
	}

	var testPath string
	if file1 != "" {
		testPath = filepath.Join(cloneTargetDir, file1)
		textDocumentDidOpen(&loc, testPath, t)
		// serve diagnostics from file scan
		assert.Eventually(t, checkForPublishedDiagnostics(workspace.Get(), testPath, -1), maxIntegTestDuration, 10*time.Millisecond)
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		f := workspace.Get().GetFolderContaining(cloneTargetDir)
		return f != nil && f.IsScanned()
	}, maxIntegTestDuration, 2*time.Millisecond)

	testPath = filepath.Join(cloneTargetDir, file2)
	textDocumentDidOpen(&loc, testPath, t)

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
					return true
				}
			}
		}
		return false
	}
}

func Test_IntegrationHoverResults(t *testing.T) {
	loc := setupServer(t)
	testutil.IntegTest(t)

	var cloneTargetDir, err = setupCustomTestRepo("https://github.com/snyk-labs/nodejs-goof", "0336589", t)
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
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
		t.Fatal(err, "Initialization failed")
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
		t.Fatal(err, "Hover retrieval failed")
	}

	hoverResult := hover.Result{}
	err = hoverResp.UnmarshalResult(&hoverResult)
	if err != nil {
		t.Fatal(err, "Hover retrieval failed")
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

	var cloneTargetDir, err = setupCustomTestRepo("https://github.com/snyk-labs/nodejs-goof", "0336589", t)
	defer os.RemoveAll(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	testPath := filepath.Join(cloneTargetDir, "app.js")

	w := workspace.Get()
	f := workspace.NewFolder(cloneTargetDir, "Test", di.Scanner(), di.HoverService())
	w.AddFolder(f)

	_ = textDocumentDidOpen(&loc, testPath, t)

	assert.Eventually(t, checkForPublishedDiagnostics(w, testPath, 6), maxIntegTestDuration, 10*time.Millisecond)
}

func textDocumentDidOpen(loc *server.Local, testPath string, t *testing.T) sglsp.DidOpenTextDocumentParams {
	testFileContent, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatal(err, "Couldn't read file content of test file")
	}

	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{
			URI:  uri.PathToUri(testPath),
			Text: string(testFileContent),
		},
	}

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		t.Fatal(err, "Call failed")
	}

	return didOpenParams
}

func setupCustomTestRepo(url string, targetCommit string, t *testing.T) (string, error) {
	workDir := xdg.DataHome // tempdir doesn't work well as it gets too long on macOS
	tempDir, err := os.MkdirTemp(workDir, "")
	if err != nil {
		t.Fatal(err, "couldn't create tempDir")
	}
	repoDir := "1"
	absoluteCloneRepoDir := filepath.Join(tempDir, repoDir)
	cmd := []string{"clone", url, repoDir}
	log.Debug().Interface("cmd", cmd).Msg("clone command")
	clone := exec.Command("git", cmd...)
	clone.Dir = tempDir
	reset := exec.Command("git", "reset", "--hard", targetCommit)
	reset.Dir = absoluteCloneRepoDir

	clean := exec.Command("git", "clean", "--force")
	clean.Dir = absoluteCloneRepoDir

	output, err := clone.CombinedOutput()
	if err != nil {
		t.Fatal(err, "clone didn't work")
	}

	log.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	log.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	log.Debug().Msg(string(output))
	return absoluteCloneRepoDir, err
}

//goland:noinspection ALL
func Test_MonitorClientProcess(t *testing.T) {
	testutil.IntegTest(t) // because we want to test it on windows, too

	// start process that just sleeps
	pidChan := make(chan int)
	go func() {
		var cmd *exec.Cmd
		if runtime.GOOS != "windows" {
			cmd = exec.Command("sleep", "2")
		} else {
			cmd = exec.Command("cmd.exe", "/c", "timeout", "/t", "2")
		}
		err := cmd.Start()
		if err != nil {
			log.Err(err).Msg("Couldn't sleep. Stopping test")
			t.Fail()
		}
		pidChan <- cmd.Process.Pid
		_ = cmd.Wait()
	}()
	pid := <-pidChan
	// make sure that we actually waited & monitored
	expectedMinimumDuration, _ := time.ParseDuration("999ms")
	assert.True(t, monitorClientProcess(pid) > expectedMinimumDuration)
}
