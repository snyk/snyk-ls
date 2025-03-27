/*
 * © 2022-2024 Snyk Limited
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
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	mcp2 "github.com/snyk/snyk-ls/internal/mcp"
	"github.com/snyk/snyk-ls/internal/storedconfig"

	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	storage2 "github.com/snyk/snyk-ls/internal/storage"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog"
	"github.com/shirou/gopsutil/process"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/codelens"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/debounce"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
)

func Start(c *config.Config) {
	var srv *jrpc2.Server

	handlers := handler.Map{}
	srv = jrpc2.NewServer(handlers, &jrpc2.ServerOptions{
		Logger: func(text string) {
			c.Logger().Trace().Str("method", "jrpc-server").Msg(text)
		},
		RPCLog:      RPCLogger{c},
		AllowPush:   true,
		Concurrency: 0, // set concurrency to < 1 causes initialization with number of cores
	})

	c.ConfigureLogging(srv)
	logger := c.Logger().With().Str("method", "server.Start").Logger()
	di.Init()
	initHandlers(srv, handlers, c)

	// start mcp server
	logger.Info().Msg("Starting up MCP Server...")
	var mcpServer *mcp2.McpLLMBinding
	go func() {
		mcpServer = mcp2.NewMcpLLMBinding(c, mcp2.WithScanner(di.Scanner()), mcp2.WithLogger(c.Logger()))
		err := mcpServer.Start()
		if err != nil {
			c.Logger().Err(err).Msg("failed to start mcp server")
		}
	}()

	// shutdown mcp server once the lsp returns from wait status
	defer func() {
		if mcpServer != nil {
			logger.Info().Msg("Shutting down MCP Server...")
			mcpServer.Shutdown(context.Background())
		}
	}()

	logger.Info().Msg("Starting up Language Server...")
	srv = srv.Start(channel.Header("")(os.Stdin, os.Stdout))
	status := srv.WaitStatus()
	if status.Err != nil {
		logger.Err(status.Err).Msg("server stopped because of error")
	} else {
		logger.Debug().Msgf("server stopped gracefully stopped=%v closed=%v", status.Stopped, status.Closed)
	}
}

const textDocumentDidOpenOperation = "textDocument/didOpen"

const textDocumentDidSaveOperation = "textDocument/didSave"

func initHandlers(srv *jrpc2.Server, handlers handler.Map, c *config.Config) {
	handlers["initialize"] = initializeHandler(c, srv)
	handlers["initialized"] = initializedHandler(c, srv)
	handlers["textDocument/didChange"] = textDocumentDidChangeHandler()
	handlers["textDocument/didClose"] = noOpHandler()
	handlers[textDocumentDidOpenOperation] = textDocumentDidOpenHandler(c)
	handlers[textDocumentDidSaveOperation] = textDocumentDidSaveHandler()
	handlers["textDocument/hover"] = textDocumentHover()
	handlers["textDocument/codeAction"] = textDocumentCodeActionHandler()
	handlers["textDocument/codeLens"] = codeLensHandler()
	handlers["textDocument/inlineValue"] = textDocumentInlineValueHandler()
	handlers["textDocument/willSave"] = noOpHandler()
	handlers["textDocument/willSaveWaitUntil"] = noOpHandler()
	handlers["codeAction/resolve"] = codeActionResolveHandler(srv)
	handlers["shutdown"] = shutdown()
	handlers["exit"] = exit(srv)
	handlers["workspace/didChangeWorkspaceFolders"] = workspaceDidChangeWorkspaceFoldersHandler(c, srv)
	handlers["workspace/willDeleteFiles"] = workspaceWillDeleteFilesHandler(c)
	handlers["workspace/didChangeConfiguration"] = workspaceDidChangeConfiguration(c, srv)
	handlers["window/workDoneProgress/cancel"] = windowWorkDoneProgressCancelHandler()
	handlers["workspace/executeCommand"] = executeCommandHandler(srv)
}

func textDocumentDidChangeHandler() jrpc2.Handler {
	debouncerMap := make(map[types.FilePath]*debounce.Debouncer)
	return handler.New(func(ctx context.Context, params sglsp.DidChangeTextDocumentParams) (any, error) {
		c := config.CurrentConfig()
		logger := c.Logger().With().Str("method", "TextDocumentDidChangeHandler").Logger()
		pathFromUri := uri.PathFromUri(params.TextDocument.URI)
		logger.Trace().Msgf("RECEIVING for %s", pathFromUri)

		folder := c.Workspace().GetFolderContaining(pathFromUri)
		if folder == nil {
			logger.Warn().Msg(string("No folder found for file " + pathFromUri))
			return nil, nil
		}

		if !folder.IsTrusted() {
			logger.Warn().Msg(string("folder not trusted for file " + pathFromUri))
			return nil, nil
		}

		di.FileWatcher().SetFileAsChanged(params.TextDocument.URI)

		debouncedCallback := func() {
			for _, change := range params.ContentChanges {
				if packageScanner, ok := di.Scanner().(scanner.PackageScanner); ok {
					go packageScanner.ScanPackages(ctx, c, pathFromUri, change.Text)
				}
			}
		}

		var debouncer = debouncerMap[pathFromUri]
		if debouncer == nil {
			debouncer = debounce.NewDebouncer(time.Millisecond*500, debouncedCallback)
			debouncerMap[pathFromUri] = debouncer
		} else {
			debouncer.UpdateDebounceCallback(debouncedCallback)
		}

		debouncer.Debounce()
		return nil, nil
	})
}

// WorkspaceWillDeleteFilesHandler handles the workspace/willDeleteFiles message that's raised by the client
// when files are deleted
func workspaceWillDeleteFilesHandler(c *config.Config) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.DeleteFilesParams) (any, error) {
		ws := c.Workspace()
		for _, file := range params.Files {
			pathFromUri := uri.PathFromUri(file.Uri)

			// Instead of branching whether it's a file or a folder, we'll attempt to remove both and the redundant case
			// will be a no-op
			ws.RemoveFolder(pathFromUri)
			ws.DeleteFile(pathFromUri)
		}
		return nil, nil
	})
}

func codeLensHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.CodeLensParams) ([]sglsp.CodeLens, error) {
		c := config.CurrentConfig()
		c.Logger().Debug().Str("method", "CodeLensHandler").Msg("RECEIVING")

		lenses := codelens.GetFor(uri.PathFromUri(params.TextDocument.URI))

		// Do not return Snyk Code Fix codelens when a doc is dirty
		isDirtyFile := di.FileWatcher().IsDirty(params.TextDocument.URI)

		defer c.Logger().Debug().Str("method", "CodeLensHandler").
			Bool("isDirtyFile", isDirtyFile).
			Int("lensCount", len(lenses)).
			Msg("SENDING")

		if !isDirtyFile {
			return lenses, nil
		}
		// if dirty, lenses don't make sense
		return nil, nil
	})
}

func workspaceDidChangeWorkspaceFoldersHandler(c *config.Config, srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.DidChangeWorkspaceFoldersParams) (any, error) {
		// The context provided by the JSON-RPC server is canceled once a new message is being processed,
		// so we don't want to propagate it to functions that start background operations
		bgCtx := context.Background()
		logger := c.Logger().With().Str("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Logger()

		logger.Info().Msg("RECEIVING")
		defer logger.Info().Msg("SENDING")
		changedFolders := c.Workspace().ChangeWorkspaceFolders(params)
		command.HandleFolders(c, bgCtx, srv, di.Notifier(), di.ScanPersister(), di.ScanStateAggregator())
		if c.IsAutoScanEnabled() {
			for _, f := range changedFolders {
				go f.ScanFolder(ctx)
			}
		}
		return nil, nil
	})
}

func initNetworkAccessHeaders() {
	engine := config.CurrentConfig().Engine()
	ua := util.GetUserAgent(engine.GetConfiguration(), config.Version)
	engine.GetNetworkAccess().AddHeaderField("User-Agent", ua.String())
}

func initializeHandler(c *config.Config, srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params types.InitializeParams) (any, error) {
		method := "initializeHandler"
		logger := c.Logger().With().Str("method", method).Logger()
		// we can only log, after we add the token to the list of forbidden outputs
		defer logger.Info().Any("params", params).Msg("RECEIVING")

		c.SetClientCapabilities(params.Capabilities)
		setClientInformation(params)
		// update storage
		file, err := storedconfig.ConfigFile(c.IdeName())
		if err != nil {
			return nil, err
		}

		storage, err := storage2.NewStorageWithCallbacks(
			storage2.WithStorageFile(file),
			storage2.WithLogger(c.Logger()),
		)
		if err != nil {
			return nil, err
		}

		c.SetStorage(storage)

		InitializeSettings(c, params.InitializationOptions)

		startClientMonitor(params, logger)

		go createProgressListener(progress.ToServerProgressChannel, srv, c.Logger())
		registerNotifier(c, srv)

		addWorkspaceFolders(c, params)

		result := types.InitializeResult{
			ServerInfo: types.ServerInfo{
				Name:    "snyk-ls",
				Version: config.LsProtocolVersion,
			},
			Capabilities: types.ServerCapabilities{
				TextDocumentSync: &sglsp.TextDocumentSyncOptionsOrKind{
					Options: &sglsp.TextDocumentSyncOptions{
						OpenClose:         true,
						Change:            sglsp.TDSKFull,
						WillSave:          true,
						WillSaveWaitUntil: true,
						Save:              &sglsp.SaveOptions{IncludeText: true},
					},
				},
				Workspace: &types.WorkspaceCapabilities{
					WorkspaceFolders: &types.WorkspaceFoldersServerCapabilities{
						Supported:           true,
						ChangeNotifications: "snyk-ls",
					},
					FileOperations: &types.FileOperationsServerCapabilities{
						WillDelete: types.FileOperationRegistrationOptions{
							Filters: []types.FileOperationFilter{
								{
									Pattern: types.FileOperationPattern{
										Glob: "**",
									},
								},
							},
						},
					},
				},
				HoverProvider:       true,
				CodeActionProvider:  &types.CodeActionOptions{ResolveProvider: true},
				CodeLensProvider:    &sglsp.CodeLensOptions{ResolveProvider: false},
				InlineValueProvider: true,
				ExecuteCommandProvider: &sglsp.ExecuteCommandOptions{
					Commands: []string{
						types.NavigateToRangeCommand,
						types.WorkspaceScanCommand,
						types.WorkspaceFolderScanCommand,
						types.OpenBrowserCommand,
						types.LoginCommand,
						types.CopyAuthLinkCommand,
						types.LogoutCommand,
						types.TrustWorkspaceFoldersCommand,
						types.OpenLearnLesson,
						types.GetLearnLesson,
						types.GetSettingsSastEnabled,
						types.GetFeatureFlagStatus,
						types.GetActiveUserCommand,
						types.CodeFixCommand,
						types.CodeSubmitFixFeedback,
						types.CodeFixDiffsCommand,
						types.CodeFixApplyEditCommand,
						types.ExecuteCLICommand,
						types.ClearCacheCommand,
						types.GenerateIssueDescriptionCommand,
						types.ReportAnalyticsCommand,
						types.ExecuteMCPToolCall,
					},
				},
			},
		}
		logger.Debug().Str("method", method).Any("result", result).Msg("SENDING")
		return result, nil
	})
}

func startClientMonitor(params types.InitializeParams, logger zerolog.Logger) {
	go func() {
		if params.ProcessID == 0 {
			// if started on its own, no need to exit or to monitor
			return
		}

		monitorClientProcess(params.ProcessID)
		logger.Info().Msgf("Shutting down as client pid %d not running anymore.", params.ProcessID)
		os.Exit(0)
	}()
}

func handleProtocolVersion(c *config.Config, noti noti.Notifier, ourProtocolVersion string, clientProtocolVersion string) {
	logger := c.Logger().With().Str("method", "handleProtocolVersion").Logger()
	if clientProtocolVersion == "" {
		logger.Debug().Msg("no client protocol version specified")
		return
	}

	if clientProtocolVersion == ourProtocolVersion || ourProtocolVersion == "development" {
		logger.Debug().Msg("protocol version is the same")
		return
	}

	if clientProtocolVersion != ourProtocolVersion {
		m := fmt.Sprintf(
			"Your Snyk plugin requires a different binary. The client-side required protocol version does not match "+
				"the running language server protocol version. Required: %s, Actual: %s. "+
				"You can update to the necessary version by enabling automatic management of binaries in the settings. "+
				"Alternatively, you can manually download the correct binary by clicking the button.",
			clientProtocolVersion,
			ourProtocolVersion,
		)
		logger.Error().Msg(m)
		actions := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()

		openBrowserCommandData := types.CommandData{
			Title:     "Download manually in browser",
			CommandId: types.OpenBrowserCommand,
			Arguments: []any{getDownloadURL(c)},
		}

		actions.Add(types.MessageAction(openBrowserCommandData.Title), openBrowserCommandData)
		doNothingKey := "Cancel"
		// if we don't provide a commandId, nothing is done
		actions.Add(types.MessageAction(doNothingKey), types.CommandData{Title: doNothingKey})

		msg := types.ShowMessageRequest{
			Message: m,
			Type:    types.Error,
			Actions: actions,
		}
		noti.Send(msg)
	}
}

func getDownloadURL(c *config.Config) (u string) {
	gafConfig := c.Engine().GetConfiguration()

	runsEmbeddedFromCLI := gafConfig.Get(cli_constants.EXECUTION_MODE_KEY) == cli_constants.EXECUTION_MODE_VALUE_EXTENSION

	if runsEmbeddedFromCLI {
		return install.GetCLIDownloadURL(c, install.DefaultBaseURL, c.Engine().GetNetworkAccess().GetUnauthorizedHttpClient())
	} else {
		return install.GetLSDownloadURL(c, c.Engine().GetNetworkAccess().GetUnauthorizedHttpClient())
	}
}

func initializedHandler(c *config.Config, srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params types.InitializedParams) (any, error) {
		// Logging these messages only after the client has been initialized.
		// Logging to the client is only allowed after the client has been initialized according to LSP protocol.
		// No reason to log the method name for these messages, because some of these values are empty and the messages
		// looks weird when including the method name.
		initialLogger := c.Logger()
		// only set our config to initialized after leaving the func
		defer func() {
			c.SetLSPInitialized(true)
		}()
		initialLogger.Info().Msg("snyk-ls: " + config.Version + " (" + util.Result(os.Executable()) + ")")
		initialLogger.Info().Msgf("CLI Path: %s", c.CliSettings().Path())
		initialLogger.Info().Msgf("CLI Installed? %t", c.CliSettings().Installed())
		initialLogger.Info().Msg("platform: " + runtime.GOOS + "/" + runtime.GOARCH)
		initialLogger.Info().Msg("https_proxy: " + os.Getenv("HTTPS_PROXY"))
		initialLogger.Info().Msg("http_proxy: " + os.Getenv("HTTP_PROXY"))
		initialLogger.Info().Msg("no_proxy: " + os.Getenv("NO_PROXY"))
		initialLogger.Info().Msg("IDE: " + c.IdeName() + "/" + c.IdeVersion())
		initialLogger.Info().Msg("snyk-plugin: " + c.IntegrationName() + "/" + c.IntegrationVersion())
		if token, err := c.TokenAsOAuthToken(); err == nil && len(token.RefreshToken) > 10 && c.AuthenticationMethod() == types.OAuthAuthentication {
			initialLogger.Info().Msgf("Truncated token: %s", token.RefreshToken[len(token.RefreshToken)-8:])
		}

		logger := c.Logger().With().Str("method", "initializedHandler").Logger()

		handleProtocolVersion(c, di.Notifier(), config.LsProtocolVersion, c.ClientProtocolVersion())

		// initialize learn cache
		go func() {
			learnService := di.LearnService()
			_, err := learnService.GetAllLessons()
			if err != nil {
				logger.Err(err).Msg("Error initializing lessons cache")
			}
			// start goroutine that keeps the cache filled
			go learnService.MaintainCache()
		}()

		// CLI & Authentication initialization - returns error if not authenticated
		err := di.Scanner().Init()
		if err != nil {
			logger.Error().Err(err).Msg("Scan initialization error, canceling scan")
			return nil, nil
		}
		command.HandleFolders(c, context.Background(), srv, di.Notifier(), di.ScanPersister(), di.ScanStateAggregator())

		// Check once for expired cache in same thread before triggering a scan.
		// Start a periodic go routine to check for the expired cache afterwards
		deleteExpiredCache(c)
		go periodicallyCheckForExpiredCache(c)

		autoScanEnabled := c.IsAutoScanEnabled()
		if autoScanEnabled {
			logger.Info().Msg("triggering workspace scan after successful initialization")
			c.Workspace().ScanWorkspace(context.Background())
		} else {
			msg := fmt.Sprintf(
				"No automatic workspace scan on initialization: autoScanEnabled=%v",
				autoScanEnabled,
			)
			logger.Info().Msg(msg)
		}
		defer func() {
			// delay sending the mcp server URL
			for c.GetMCPServerURL() == nil {
				// wait until the server URL is available
				time.Sleep(500 * time.Millisecond)
			}
			di.Notifier().Send(types.McpServerURLParams{URL: c.GetMCPServerURL().String()})
		}()
		return nil, nil
	})
}

func startOfflineDetection(c *config.Config) { //nolint:unused // this is gonna be used soon
	go func() {
		timeout := time.Second * 10
		client := c.Engine().GetNetworkAccess().GetUnauthorizedHttpClient()
		client.Timeout = timeout - 1
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		type logLevelConfigurable interface {
			SetLogLevel(level zerolog.Level)
		}

		if loggingRoundTripper, ok := client.Transport.(logLevelConfigurable); ok {
			loggingRoundTripper.SetLogLevel(zerolog.ErrorLevel)
		}

		for {
			u := "https://downloads.snyk.io/cli/stable/version" // FIXME: which URL to use?
			response, err := client.Get(u)
			if err != nil {
				if !c.Offline() {
					msg := fmt.Sprintf("Cannot connect to %s. You need to fix your networking for Snyk to work.", u)
					reportedErr := errors.Join(err, errors.New(msg))
					c.Logger().Err(reportedErr).Send()
					di.Notifier().SendShowMessage(sglsp.Warning, msg)
				}
				c.SetOffline(true)
			} else {
				if c.Offline() {
					msg := fmt.Sprintf("Snyk is active again. We were able to reach %s", u)
					di.Notifier().SendShowMessage(sglsp.Info, msg)
					c.Logger().Info().Msg(msg)
				}
				c.SetOffline(false)
			}
			if response != nil {
				_ = response.Body.Close()
			}
			time.Sleep(timeout)
		}
	}()
}

func deleteExpiredCache(c *config.Config) {
	w := c.Workspace()
	var folderList []types.FilePath
	for _, f := range w.Folders() {
		folderList = append(folderList, f.Path())
	}
	c.Workspace().GetScanSnapshotClearerExister().Clear(folderList, true)
}

func periodicallyCheckForExpiredCache(c *config.Config) {
	for {
		deleteExpiredCache(c)
		time.Sleep(time.Duration(persistence.ExpirationInSeconds) * time.Second)
	}
}

func addWorkspaceFolders(c *config.Config, params types.InitializeParams) {
	const method = "addWorkspaceFolders"
	w := c.Workspace()
	if len(params.WorkspaceFolders) > 0 {
		for _, workspaceFolder := range params.WorkspaceFolders {
			c.Logger().Info().Str("method", method).Msgf("Adding workspaceFolder %v", workspaceFolder)
			f := workspace.NewFolder(
				c,
				uri.PathFromUri(workspaceFolder.Uri),
				workspaceFolder.Name,
				di.Scanner(),
				di.HoverService(),
				di.ScanNotifier(),
				di.Notifier(),
				di.ScanPersister(),
				di.ScanStateAggregator())
			w.AddFolder(f)
		}
	} else {
		if params.RootURI != "" {
			f := workspace.NewFolder(
				c,
				uri.PathFromUri(params.RootURI),
				params.ClientInfo.Name,
				di.Scanner(),
				di.HoverService(),
				di.ScanNotifier(),
				di.Notifier(),
				di.ScanPersister(),
				di.ScanStateAggregator())
			w.AddFolder(f)
		} else if params.RootPath != "" {
			f := workspace.NewFolder(
				c,
				types.FilePath(params.RootPath),
				params.ClientInfo.Name,
				di.Scanner(),
				di.HoverService(),
				di.ScanNotifier(),
				di.Notifier(),
				di.ScanPersister(),
				di.ScanStateAggregator())
			w.AddFolder(f)
		}
	}
}

// setClientInformation sets the integration name and version from the client information.
// The integration version refers to the plugin version, not the IDE version.
// The function attempts to pull the values from the initialization options, then the client info, and finally
// from the environment variables.
func setClientInformation(initParams types.InitializeParams) {
	var integrationName, integrationVersion string
	clientInfoName := initParams.ClientInfo.Name
	clientInfoVersion := initParams.ClientInfo.Version

	if initParams.InitializationOptions.IntegrationName != "" {
		integrationName = initParams.InitializationOptions.IntegrationName
		integrationVersion = initParams.InitializationOptions.IntegrationVersion
	} else if clientInfoName != "" {
		integrationName = strings.ToUpper(strings.Replace(clientInfoName, " ", "_", -1))
	} else if integrationNameEnvVar := os.Getenv(cli.IntegrationNameEnvVarKey); integrationNameEnvVar != "" {
		integrationName = integrationNameEnvVar
		integrationVersion = os.Getenv(cli.IntegrationVersionEnvVarKey)
	} else {
		return
	}

	// Fallback because Visual Studio doesn't send initParams.ClientInfo
	if clientInfoName == "" && clientInfoVersion == "" && strings.Contains(integrationName, "@@") && strings.Contains(integrationVersion, "@@") {
		clientInfoName = strings.Split(integrationName, "@@")[0]
		integrationName = strings.Split(integrationName, "@@")[1]
		clientInfoVersion = strings.Split(integrationVersion, "@@")[0]
		integrationVersion = strings.Split(integrationVersion, "@@")[1]
	}

	c := config.CurrentConfig()
	c.SetIntegrationName(integrationName)
	c.SetIntegrationVersion(integrationVersion)
	c.SetIdeName(clientInfoName)
	c.SetIdeVersion(clientInfoVersion)

	initNetworkAccessHeaders()
}

func monitorClientProcess(pid int) time.Duration {
	start := time.Now()
	for {
		exists, err := process.PidExists(int32(pid))
		if !exists || err != nil {
			break
		}
		time.Sleep(time.Millisecond * 1000)
	}
	return time.Since(start)
}

func shutdown() jrpc2.Handler {
	return handler.New(func(ctx context.Context) (any, error) {
		c := config.CurrentConfig()
		logger := c.Logger().With().Str("method", "Shutdown").Logger()
		logger.Info().Msg("ENTERING")
		defer logger.Info().Msg("RETURNING")
		di.ErrorReporter().FlushErrorReporting()

		disposeProgressListener()
		di.Notifier().DisposeListener()
		return nil, nil
	})
}

func exit(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(_ context.Context) (any, error) {
		c := config.CurrentConfig()
		logger := c.Logger().With().Str("method", "Exit").Logger()
		logger.Info().Msg("ENTERING")
		logger.Info().Msg("Flushing error reporting...")
		di.ErrorReporter().FlushErrorReporting()
		logger.Info().Msg("Stopping server...")
		srv.Stop()
		return nil, nil
	})
}

func logError(logger *zerolog.Logger, err error, method string) {
	if err != nil {
		logger.Err(err).Str("method", method)
		di.ErrorReporter().CaptureError(err)
	}
}

func textDocumentDidOpenHandler(c *config.Config) jrpc2.Handler {
	return handler.New(func(_ context.Context, params sglsp.DidOpenTextDocumentParams) (any, error) {
		filePath := uri.PathFromUri(params.TextDocument.URI)
		filePathString := string(filePath)
		logger := c.Logger().With().Str("method", "TextDocumentDidOpenHandler").Str("documentURI", filePathString).Logger()
		logger.Info().Msg("Receiving")

		folder := c.Workspace().GetFolderContaining(filePath)
		if folder == nil {
			logger.Warn().Msg("No folder found for file " + filePathString)
			return nil, nil
		}

		if !folder.IsTrusted() {
			logger.Warn().Msg("folder not trusted for file " + filePathString)
			return nil, nil
		}

		fip, ok := folder.(snyk.FilteringIssueProvider)
		if !ok {
			logger.Warn().Msg("folder is not a filtering issue provider")
			return nil, nil
		}

		filteredIssues := fip.FilterIssues(fip.Issues(), c.DisplayableIssueTypes())

		if len(filteredIssues) > 0 {
			logger.Debug().Msg("Sending cached issues")
			diagnosticParams := types.PublishDiagnosticsParams{
				URI:         params.TextDocument.URI,
				Diagnostics: converter.ToDiagnostics(filteredIssues[filePath]),
			}
			di.Notifier().Send(diagnosticParams)
		}

		if sc, ok := di.Scanner().(scanner.PackageScanner); ok {
			sc.ScanPackages(context.Background(), c, filePath, "")
		}
		return nil, nil
	})
}

func textDocumentDidSaveHandler() jrpc2.Handler {
	return handler.New(func(_ context.Context, params sglsp.DidSaveTextDocumentParams) (any, error) {
		// The context provided by the JSON-RPC server is canceled once a new message is being processed,
		// so we don't want to propagate it to functions that start background operations
		bgCtx := context.Background()
		c := config.CurrentConfig()
		logger := c.Logger().With().Str("method", "TextDocumentDidSaveHandler").Logger()
		logger.Debug().Interface("params", params).Msg("Receiving")

		autoScanEnabled := c.IsAutoScanEnabled()

		di.FileWatcher().SetFileAsSaved(params.TextDocument.URI)
		filePath := uri.PathFromUri(params.TextDocument.URI)

		folder := c.Workspace().GetFolderContaining(filePath)
		if folder == nil {
			logger.Warn().Msg(string("No folder found for file " + filePath))
			return nil, nil
		}

		if !folder.IsTrusted() {
			logger.Warn().Msg(string("folder not trusted for file " + filePath))
			return nil, nil
		}

		if autoScanEnabled && uri.IsDotSnykFile(params.TextDocument.URI) {
			go folder.ScanFolder(bgCtx)
			return nil, nil
		}

		if autoScanEnabled {
			go folder.ScanFile(bgCtx, filePath)
		} else {
			logger.Warn().Msg("Not scanning, auto-scan is disabled")
		}
		return nil, nil
	})
}

func textDocumentHover() jrpc2.Handler {
	return handler.New(func(_ context.Context, params hover.Params) (hover.Result, error) {
		c := config.CurrentConfig()
		c.Logger().Debug().Str("method", "TextDocumentHover").Interface("params", params).Msg("RECEIVING")

		pathFromUri := uri.PathFromUri(params.TextDocument.URI)
		hoverResult := di.HoverService().GetHover(pathFromUri, converter.FromPosition(params.Position))
		return hoverResult, nil
	})
}

func windowWorkDoneProgressCancelHandler() jrpc2.Handler {
	return handler.New(func(_ context.Context, params types.WorkdoneProgressCancelParams) (any, error) {
		c := config.CurrentConfig()
		c.Logger().Debug().Str("method", "WindowWorkDoneProgressCancelHandler").Interface("params", params).Msg("RECEIVING")
		progress.Cancel(params.Token)
		return nil, nil
	})
}

func codeActionResolveHandler(server types.Server) handler.Func {
	c := config.CurrentConfig()
	return handler.New(ResolveCodeActionHandler(c, di.CodeActionService(), server))
}

func textDocumentCodeActionHandler() handler.Func {
	c := config.CurrentConfig()
	return handler.New(GetCodeActionHandler(c))
}

func noOpHandler() jrpc2.Handler {
	return handler.New(func(_ context.Context, params sglsp.DidCloseTextDocumentParams) (any, error) {
		c := config.CurrentConfig()
		c.Logger().Debug().Str("method", "NoOpHandler").Interface("params", params).Msg("RECEIVING")
		return nil, nil
	})
}

type RPCLogger struct {
	c *config.Config
}

func (r RPCLogger) LogRequest(_ context.Context, req *jrpc2.Request) {
	r.c.Logger().Debug().Msgf("Incoming JSON-RPC request. Method=%s. ID=%s. Is notification=%v.",
		req.Method(),
		req.ID(),
		req.IsNotification())
}

func (r RPCLogger) LogResponse(_ context.Context, rsp *jrpc2.Response) {
	logger := r.c.Logger()
	if rsp.Error() != nil {
		logger.Err(rsp.Error()).Interface("rsp", *rsp).Msg("Outgoing JSON-RPC response error")
	}
	logger.Debug().Msgf("Outgoing JSON-RPC response. ID=%s", rsp.ID())
}
