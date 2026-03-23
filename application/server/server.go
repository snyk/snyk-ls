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
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"

	"github.com/snyk/snyk-ls/internal/folderconfig"
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
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/data_structure"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
)

var cacheCheckCancel context.CancelFunc

func Start(engine workflow.Engine, tokenService *config.TokenServiceImpl) {
	var srv *jrpc2.Server
	conf := engine.GetConfiguration()

	handlers := handler.Map{}
	srv = jrpc2.NewServer(handlers, &jrpc2.ServerOptions{
		Logger: func(text string) {
			engine.GetLogger().Trace().Str("method", "jrpc-server").Msg(text)
		},
		RPCLog:      RPCLogger{engine.GetLogger()},
		AllowPush:   true,
		Concurrency: 0, // set concurrency to < 1 causes initialization with number of cores
	})

	config.SetupLogging(engine, tokenService, srv)
	logger := engine.GetLogger()
	startLogger := logger.With().Str("method", "server.Start").Logger()
	di.Init(engine, tokenService)
	initHandlers(srv, handlers, conf, engine, logger)

	startLogger.Info().Msg("Starting up Language Server...")
	srv = srv.Start(channel.LSP(os.Stdin, os.Stdout))
	status := srv.WaitStatus()
	if status.Err != nil {
		startLogger.Err(status.Err).Msg("server stopped because of error")
	} else {
		startLogger.Debug().Msgf("server stopped gracefully stopped=%v closed=%v", status.Stopped, status.Closed)
	}
}

// withContext wraps a jrpc2.Handler to inject logger, configuration, engine, and ConfigResolver into the request context.
func withContext(h jrpc2.Handler, logger *zerolog.Logger, conf configuration.Configuration, engine workflow.Engine, configResolver types.ConfigResolverInterface) jrpc2.Handler {
	return func(ctx context.Context, req *jrpc2.Request) (any, error) {
		ctx = ctx2.NewContextWithLogger(ctx, logger)
		ctx = ctx2.NewContextWithConfiguration(ctx, conf)
		ctx = ctx2.NewContextWithEngine(ctx, engine)
		if configResolver != nil {
			ctx = ctx2.NewContextWithConfigResolver(ctx, configResolver)
		}
		return h(ctx, req)
	}
}

const textDocumentDidOpenOperation = "textDocument/didOpen"

const textDocumentDidSaveOperation = "textDocument/didSave"

func initHandlers(srv *jrpc2.Server, handlers handler.Map, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger) {
	enrich := func(h jrpc2.Handler) jrpc2.Handler {
		return withContext(h, logger, conf, engine, di.ConfigResolver())
	}
	handlers["initialize"] = enrich(initializeHandler(conf, engine, srv))
	handlers["initialized"] = enrich(initializedHandler(conf, engine, srv))
	handlers["textDocument/didChange"] = enrich(textDocumentDidChangeHandler(conf))
	handlers["textDocument/didClose"] = enrich(noOpHandler())
	handlers[textDocumentDidOpenOperation] = enrich(textDocumentDidOpenHandler(conf))
	handlers[textDocumentDidSaveOperation] = enrich(textDocumentDidSaveHandler(conf))
	handlers["textDocument/hover"] = enrich(textDocumentHover())
	handlers["textDocument/codeAction"] = enrich(textDocumentCodeActionHandler(logger))
	handlers["textDocument/codeLens"] = enrich(codeLensHandler())
	handlers["textDocument/inlineValue"] = enrich(textDocumentInlineValueHandler())
	handlers["textDocument/willSave"] = enrich(noOpHandler())
	handlers["textDocument/willSaveWaitUntil"] = enrich(noOpHandler())
	handlers["codeAction/resolve"] = enrich(codeActionResolveHandler(logger, srv))
	handlers["shutdown"] = enrich(shutdownHandler())
	handlers["exit"] = enrich(exitHandler(srv))
	handlers["workspace/didChangeWorkspaceFolders"] = enrich(workspaceDidChangeWorkspaceFoldersHandler(conf, engine, srv))
	handlers["workspace/willDeleteFiles"] = enrich(workspaceWillDeleteFilesHandler(conf))
	handlers["workspace/didChangeConfiguration"] = enrich(workspaceDidChangeConfiguration(conf, srv))
	handlers["window/workDoneProgress/cancel"] = enrich(windowWorkDoneProgressCancelHandler())
	handlers["workspace/executeCommand"] = enrich(executeCommandHandler(srv))
	handlers["$/cancelRequest"] = cancelRequestHandler(srv)
}

func textDocumentDidChangeHandler(conf configuration.Configuration) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidChangeTextDocumentParams) (any, error) {
		logger := ctx2.LoggerFromContext(ctx).With().Str("method", "TextDocumentDidChangeHandler").Logger()
		pathFromUri := uri.PathFromUri(params.TextDocument.URI)
		logger.Trace().Msgf("RECEIVING for %s", pathFromUri)

		folder := config.GetWorkspace(conf).GetFolderContaining(pathFromUri)
		if folder == nil {
			logger.Warn().Msg(string("No folder found for file " + pathFromUri))
			return nil, nil
		}

		if !folder.IsTrusted() {
			logger.Warn().Msg(string("folder not trusted for file " + pathFromUri))
			return nil, nil
		}

		di.FileWatcher().SetFileAsChanged(params.TextDocument.URI)

		return nil, nil
	})
}

// WorkspaceWillDeleteFilesHandler handles the workspace/willDeleteFiles message that's raised by the client
// when files are deleted
func workspaceWillDeleteFilesHandler(conf configuration.Configuration) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.DeleteFilesParams) (any, error) {
		w := config.GetWorkspace(conf)
		for _, file := range params.Files {
			pathFromUri := types.PathKey(uri.PathFromUri(file.Uri))

			// Instead of branching whether it's a file or a folder, we'll attempt to remove both and the redundant case
			// will be a no-op
			w.RemoveFolder(pathFromUri)
			w.DeleteFile(pathFromUri)
		}
		return nil, nil
	})
}

func codeLensHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.CodeLensParams) ([]sglsp.CodeLens, error) {
		logger := ctx2.LoggerFromContext(ctx)
		logger.Debug().Str("method", "CodeLensHandler").Msg("RECEIVING")

		conf, ok := ctx2.ConfigurationFromContext(ctx)
		if !ok {
			return []sglsp.CodeLens{}, nil
		}
		lenses := codelens.GetFor(conf, logger, uri.PathFromUri(params.TextDocument.URI))

		isDirtyFile := di.FileWatcher().IsDirty(params.TextDocument.URI)

		defer logger.Debug().Str("method", "CodeLensHandler").
			Bool("isDirtyFile", isDirtyFile).
			Int("lensCount", len(lenses)).
			Msg("SENDING")

		if !isDirtyFile {
			return lenses, nil
		}
		return nil, nil
	})
}

func workspaceDidChangeWorkspaceFoldersHandler(conf configuration.Configuration, engine workflow.Engine, srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.DidChangeWorkspaceFoldersParams) (any, error) {
		// The context provided by the JSON-RPC server is canceled once a new message is being processed,
		// so we don't want to propagate it to functions that start background operations
		bgCtx := context.Background()
		logger := ctx2.LoggerFromContext(ctx).With().Str("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Logger()

		logger.Info().Msg("RECEIVING")
		defer logger.Info().Msg("SENDING")
		changedFolders := config.GetWorkspace(conf).ChangeWorkspaceFolders(params)

		if di.AuthenticationService().IsAuthenticated() {
			di.LdxSyncService().RefreshConfigFromLdxSync(bgCtx, conf, engine, &logger, changedFolders, di.Notifier())
		}

		command.HandleFolders(conf, engine, &logger, bgCtx, srv, di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver())
		for _, f := range changedFolders {
			if f.IsAutoScanEnabled() {
				go f.ScanFolder(bgCtx)
			}
		}
		return nil, nil
	})
}

func initNetworkAccessHeaders(engine workflow.Engine) {
	engineConfig := engine.GetConfiguration()
	ua := util.GetUserAgent(engineConfig, config.Version)
	engine.GetNetworkAccess().AddHeaderField("x-snyk-ide", "snyk-ls-"+ua.AppVersion)
	engine.GetNetworkAccess().AddHeaderField("User-Agent", ua.String())
}

func initializeHandler(conf configuration.Configuration, engine workflow.Engine, srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params types.InitializeParams) (any, error) {
		method := "initializeHandler"
		logger := ctx2.LoggerFromContext(ctx).With().Str("method", method).Logger()

		conf.Set(types.SettingClientCapabilities, params.Capabilities)
		setClientInformation(conf, engine, params)
		file, err := folderconfig.ConfigFile(conf.GetString(configuration.INTEGRATION_ENVIRONMENT))
		if err != nil {
			return nil, err
		}

		storage, err := storage2.NewStorageWithCallbacks(
			storage2.WithStorageFile(file),
			storage2.WithLogger(&logger),
		)
		if err != nil {
			return nil, err
		}

		config.SetupStorage(conf, storage, &logger)

		addWorkspaceFolders(conf, &logger, engine, params)
		di.LdxSyncService().RefreshConfigFromLdxSync(ctx, conf, engine, &logger, config.GetWorkspace(conf).Folders(), nil)
		InitializeSettings(conf, engine, &logger, params.InitializationOptions)

		startClientMonitor(params, logger)

		go createProgressListener(progress.ToServerProgressChannel, srv, &logger)
		registerNotifier(conf, &logger, srv)

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
						types.SubmitIgnoreRequest,
						types.GetSettingsSastEnabled,
						types.GetFeatureFlagStatus,
						types.GetActiveUserCommand,
						types.CodeFixCommand,
						types.CodeSubmitFixFeedback,
						types.CodeFixDiffsCommand,
						types.CodeFixApplyEditCommand,
						types.ExecuteCLICommand,
						types.ConnectivityCheckCommand,
						types.DirectoryDiagnosticsCommand,
						types.ClearCacheCommand,
						types.GenerateIssueDescriptionCommand,
						types.ReportAnalyticsCommand,
						types.WorkspaceConfigurationCommand,
						types.GetTreeView,
						types.ToggleTreeFilter,
						types.SetNodeExpanded,
						types.ShowScanErrorDetails,
						types.UpdateFolderConfig,
					},
				},
			},
		}
		// we can only log, after we add the token to the list of forbidden outputs
		logger.Debug().Any("params", params).Msg("RECEIVING")
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

func handleProtocolVersion(conf configuration.Configuration, engine workflow.Engine, n noti.Notifier, logger *zerolog.Logger, ourProtocolVersion string, clientProtocolVersion string) {
	l := logger.With().Str("method", "handleProtocolVersion").Logger()
	if clientProtocolVersion == "" {
		l.Debug().Msg("no client protocol version specified")
		return
	}

	if clientProtocolVersion == ourProtocolVersion || ourProtocolVersion == "development" {
		l.Debug().Msg("protocol version is the same")
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
		l.Error().Msg(m)
		actions := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()

		openBrowserCommandData := types.CommandData{
			Title:     "Download manually in browser",
			CommandId: types.OpenBrowserCommand,
			Arguments: []any{getDownloadURL(conf, engine, clientProtocolVersion)},
		}

		actions.Add(types.MessageAction(openBrowserCommandData.Title), openBrowserCommandData)
		doNothingKey := "Cancel"
		actions.Add(types.MessageAction(doNothingKey), types.CommandData{Title: doNothingKey})

		msg := types.ShowMessageRequest{
			Message: m,
			Type:    types.Error,
			Actions: actions,
		}
		n.Send(msg)
	}
}

func getDownloadURL(conf configuration.Configuration, engine workflow.Engine, protocolVersion string) (u string) {
	runsEmbeddedFromCLI := conf.Get(cli_constants.EXECUTION_MODE_KEY) == cli_constants.EXECUTION_MODE_VALUE_EXTENSION

	if runsEmbeddedFromCLI {
		return install.GetCLIDownloadURLForProtocol(engine, install.DefaultBaseURL, engine.GetNetworkAccess().GetUnauthorizedHttpClient(), protocolVersion)
	} else {
		return install.GetLSDownloadURLForProtocol(engine, engine.GetNetworkAccess().GetUnauthorizedHttpClient(), protocolVersion)
	}
}

func initializedHandler(conf configuration.Configuration, engine workflow.Engine, srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params types.InitializedParams) (any, error) {
		initialLogger := ctx2.LoggerFromContext(ctx)
		defer func() {
			conf.Set(types.SettingIsLspInitialized, true)
		}()
		initialLogger.Info().Msg("snyk-ls: " + config.Version + " (" + util.Result(os.Executable()) + ")")
		cliPath := di.ConfigResolver().GetString(types.SettingCliPath, nil)
		if cliPath != "" {
			cliPath = filepath.Clean(cliPath)
		}
		initialLogger.Info().Msgf("CLI Path: %s", cliPath)
		initialLogger.Info().Msgf("CLI Installed? %t", config.CliInstalled(conf))
		initialLogger.Info().Msg("platform: " + runtime.GOOS + "/" + runtime.GOARCH)
		initialLogger.Info().Msg("https_proxy: " + os.Getenv("HTTPS_PROXY"))
		initialLogger.Info().Msg("http_proxy: " + os.Getenv("HTTP_PROXY"))
		initialLogger.Info().Msg("no_proxy: " + os.Getenv("NO_PROXY"))
		initialLogger.Info().Msg("IDE: " + conf.GetString(configuration.INTEGRATION_ENVIRONMENT) + "/" + conf.GetString(configuration.INTEGRATION_ENVIRONMENT_VERSION))
		initialLogger.Info().Msg("snyk-plugin: " + conf.GetString(configuration.INTEGRATION_NAME) + "/" + conf.GetString(configuration.INTEGRATION_VERSION))
		if token, err := config.ParseOAuthToken(config.GetToken(conf), initialLogger); err == nil && len(token.RefreshToken) > 10 && config.GetAuthenticationMethodFromConfig(conf) == types.OAuthAuthentication {
			initialLogger.Info().Msgf("Truncated token: %s", token.RefreshToken[len(token.RefreshToken)-8:])
		}

		if conf.GetBool(configuration.CONFIG_CACHE_DISABLED) {
			initialLogger.Info().Msg("config cache: disabled")
		} else {
			initialLogger.Info().Msgf("config cache: %v", conf.GetDuration(configuration.CONFIG_CACHE_TTL))
		}

		logger := initialLogger.With().Str("method", "initializedHandler").Logger()

		handleProtocolVersion(conf, engine, di.Notifier(), &logger, config.LsProtocolVersion, di.ConfigResolver().GetString(types.SettingClientProtocolVersion, nil))

		go func() {
			learnService := di.LearnService()
			_, err := learnService.GetAllLessons()
			if err != nil {
				logger.Err(err).Msg("Error initializing lessons cache")
			}
			go learnService.MaintainCacheFunc()
		}()

		err := di.Scanner().Init(ctx)
		if err != nil {
			logger.Error().Err(err).Msg("Scan initialization error, canceling scan")
			return nil, nil
		}
		command.HandleFolders(conf, engine, &logger, context.Background(), srv, di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver())

		deleteExpiredCache(conf)
		cacheCtx, cancel := context.WithCancel(context.Background())
		cacheCheckCancel = cancel
		go periodicallyCheckForExpiredCache(cacheCtx, conf)

		autoScanEnabled := di.ConfigResolver().GetBool(types.SettingScanAutomatic, nil)
		if autoScanEnabled {
			logger.Info().Msg("triggering workspace scan after successful initialization")
			config.GetWorkspace(conf).ScanWorkspace(context.Background())
		} else {
			msg := fmt.Sprintf(
				"No automatic workspace scan on initialization: autoScanEnabled=%v",
				autoScanEnabled,
			)
			logger.Info().Msg(msg)
		}

		return nil, nil
	})
}

func startOfflineDetection(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger) { //nolint:unused // this is gonna be used soon
	go func() {
		timeout := time.Second * 10
		client := engine.GetNetworkAccess().GetUnauthorizedHttpClient()
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
				if !di.ConfigResolver().GetBool(types.SettingOffline, nil) {
					msg := fmt.Sprintf("Cannot connect to %s. You need to fix your networking for Snyk to work.", u)
					reportedErr := errors.Join(err, errors.New(msg))
					logger.Err(reportedErr).Send()
					di.Notifier().SendShowMessage(sglsp.Warning, msg)
				}
				conf.Set(configresolver.UserGlobalKey(types.SettingOffline), true)
			} else {
				if di.ConfigResolver().GetBool(types.SettingOffline, nil) {
					msg := fmt.Sprintf("Snyk is active again. We were able to reach %s", u)
					di.Notifier().SendShowMessage(sglsp.Info, msg)
					logger.Info().Msg(msg)
				}
				conf.Set(configresolver.UserGlobalKey(types.SettingOffline), false)
			}
			if response != nil {
				_ = response.Body.Close()
			}
			time.Sleep(timeout)
		}
	}()
}

func deleteExpiredCache(conf configuration.Configuration) {
	w := config.GetWorkspace(conf)
	var folderList []types.FilePath
	for _, f := range w.Folders() {
		folderList = append(folderList, f.Path())
	}
	w.GetScanSnapshotClearerExister().Clear(folderList, true)
}

func periodicallyCheckForExpiredCache(ctx context.Context, conf configuration.Configuration) {
	ticker := time.NewTicker(time.Duration(persistence.ExpirationInSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleteExpiredCache(conf)
		}
	}
}

func addWorkspaceFolders(conf configuration.Configuration, logger *zerolog.Logger, engine workflow.Engine, params types.InitializeParams) {
	const method = "addWorkspaceFolders"
	w := config.GetWorkspace(conf)

	if len(params.WorkspaceFolders) > 0 {
		for _, workspaceFolder := range params.WorkspaceFolders {
			logger.Info().Str("method", method).Msgf("Adding workspaceFolder %v", workspaceFolder)

			f := workspace.NewFolder(
				conf,
				logger,
				types.PathKey(uri.PathFromUri(workspaceFolder.Uri)),
				workspaceFolder.Name,
				di.Scanner(),
				di.HoverService(),
				di.ScanNotifier(),
				di.Notifier(),
				di.ScanPersister(),
				di.ScanStateAggregator(),
				di.FeatureFlagService(),
				di.ConfigResolver(),
				engine)
			w.AddFolder(f)
		}
	} else {
		if params.RootURI != "" {
			f := workspace.NewFolder(
				conf,
				logger,
				types.PathKey(uri.PathFromUri(params.RootURI)),
				params.ClientInfo.Name,
				di.Scanner(),
				di.HoverService(),
				di.ScanNotifier(),
				di.Notifier(),
				di.ScanPersister(),
				di.ScanStateAggregator(),
				di.FeatureFlagService(),
				di.ConfigResolver(),
				engine)
			w.AddFolder(f)
		} else if params.RootPath != "" {
			f := workspace.NewFolder(
				conf,
				logger,
				types.FilePath(params.RootPath),
				params.ClientInfo.Name,
				di.Scanner(),
				di.HoverService(),
				di.ScanNotifier(),
				di.Notifier(),
				di.ScanPersister(),
				di.ScanStateAggregator(),
				di.FeatureFlagService(),
				di.ConfigResolver(),
				engine)
			w.AddFolder(f)
		}
	}
}

// setClientInformation sets the integration name and version from the client information.
// The integration version refers to the plugin version, not the IDE version.
// The function attempts to pull the values from the initialization options, then the client info, and finally
// from the environment variables.
func setClientInformation(conf configuration.Configuration, engine workflow.Engine, initParams types.InitializeParams) {
	var integrationName, integrationVersion string
	clientInfoName := initParams.ClientInfo.Name
	clientInfoVersion := initParams.ClientInfo.Version

	if initParams.InitializationOptions.IntegrationName != "" {
		integrationName = initParams.InitializationOptions.IntegrationName
		integrationVersion = initParams.InitializationOptions.IntegrationVersion
	} else if clientInfoName != "" {
		integrationName = strings.ToUpper(strings.ReplaceAll(clientInfoName, " ", "_"))
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

	conf.Set(configuration.INTEGRATION_NAME, integrationName)
	conf.Set(configuration.INTEGRATION_VERSION, integrationVersion)
	conf.Set(configuration.INTEGRATION_ENVIRONMENT, clientInfoName)
	conf.Set(configuration.INTEGRATION_ENVIRONMENT_VERSION, clientInfoVersion)

	initNetworkAccessHeaders(engine)
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

func shutdownHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context) (any, error) {
		logger := ctx2.LoggerFromContext(ctx).With().Str("method", "Shutdown").Logger()
		logger.Info().Msg("ENTERING")
		defer logger.Info().Msg("RETURNING")
		di.ErrorReporter().FlushErrorReporting()

		if cacheCheckCancel != nil {
			cacheCheckCancel()
		}
		di.DisposeTreeEmitter()
		disposeProgressListener()
		di.Notifier().DisposeListener()
		command.StopPendingRescanTimers()
		return nil, nil
	})
}

func exitHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context) (any, error) {
		logger := ctx2.LoggerFromContext(ctx).With().Str("method", "Exit").Logger()
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

func textDocumentDidOpenHandler(conf configuration.Configuration) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidOpenTextDocumentParams) (any, error) {
		filePath := uri.PathFromUri(params.TextDocument.URI)
		filePathString := string(filePath)
		logger := ctx2.LoggerFromContext(ctx).With().Str("method", "TextDocumentDidOpenHandler").Str("documentURI", filePathString).Logger()
		logger.Info().Msg("Receiving")

		folder := config.GetWorkspace(conf).GetFolderContaining(filePath)
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

		filteredIssues := fip.FilterIssues(fip.Issues(), folder.DisplayableIssueTypes())

		if len(filteredIssues) > 0 {
			logger.Debug().Msg("Sending cached issues")
			diagnosticParams := types.PublishDiagnosticsParams{
				URI:         params.TextDocument.URI,
				Diagnostics: converter.ToDiagnostics(filteredIssues[filePath]),
			}
			di.Notifier().Send(diagnosticParams)
		}

		return nil, nil
	})
}

func textDocumentDidSaveHandler(conf configuration.Configuration) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidSaveTextDocumentParams) (any, error) {
		bgCtx := context.Background()
		logger := ctx2.LoggerFromContext(ctx).With().Str("method", "TextDocumentDidSaveHandler").Logger()
		logger.Debug().Interface("params", params).Msg("Receiving")

		di.FileWatcher().SetFileAsSaved(params.TextDocument.URI)
		filePath := uri.PathFromUri(params.TextDocument.URI)

		folder := config.GetWorkspace(conf).GetFolderContaining(filePath)
		if folder == nil {
			logger.Warn().Msg(string("No folder found for file " + filePath))
			return nil, nil
		}

		if !folder.IsTrusted() {
			logger.Warn().Msg(string("folder not trusted for file " + filePath))
			return nil, nil
		}

		if folder.IsAutoScanEnabled() && uri.IsDotSnykFile(params.TextDocument.URI) {
			go folder.ScanFolder(bgCtx)
			return nil, nil
		}

		if folder.IsAutoScanEnabled() {
			go folder.ScanFile(bgCtx, filePath)
		} else {
			logger.Warn().Msg("Not scanning, auto-scan is disabled")
		}
		return nil, nil
	})
}

func textDocumentHover() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params hover.Params) (hover.Result, error) {
		ctx2.LoggerFromContext(ctx).Debug().Str("method", "TextDocumentHover").Interface("params", params).Msg("RECEIVING")

		pathFromUri := uri.PathFromUri(params.TextDocument.URI)
		hoverResult := di.HoverService().GetHover(pathFromUri, converter.FromPosition(params.Position))
		return hoverResult, nil
	})
}

func windowWorkDoneProgressCancelHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.WorkdoneProgressCancelParams) (any, error) {
		ctx2.LoggerFromContext(ctx).Debug().Str("method", "WindowWorkDoneProgressCancelHandler").Interface("params", params).Msg("RECEIVING")
		progress.Cancel(params.Token)
		return nil, nil
	})
}

func codeActionResolveHandler(logger *zerolog.Logger, server types.Server) handler.Func {
	return handler.New(ResolveCodeActionHandler(logger, di.CodeActionService(), server))
}

func textDocumentCodeActionHandler(logger *zerolog.Logger) handler.Func {
	return handler.New(GetCodeActionHandler(logger))
}

func cancelRequestHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(_ context.Context, params sglsp.CancelParams) (any, error) {
		srv.CancelRequest(params.ID.String())
		return nil, nil
	})
}

func noOpHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidCloseTextDocumentParams) (any, error) {
		ctx2.LoggerFromContext(ctx).Debug().Str("method", "NoOpHandler").Interface("params", params).Msg("RECEIVING")
		return nil, nil
	})
}

type RPCLogger struct {
	logger *zerolog.Logger
}

func (r RPCLogger) LogRequest(_ context.Context, req *jrpc2.Request) {
	r.logger.Debug().Msgf("Incoming JSON-RPC request. Method=%s. ID=%s. Is notification=%v.",
		req.Method(),
		req.ID(),
		req.IsNotification())
}

func (r RPCLogger) LogResponse(_ context.Context, rsp *jrpc2.Response) {
	if rsp.Error() != nil {
		r.logger.Err(rsp.Error()).
			Str("rsp.ID", rsp.ID()).
			Interface("rsp.Error", rsp.Error()).
			Msg("Outgoing JSON-RPC response error")
	}
	r.logger.Debug().Msgf("Outgoing JSON-RPC response. ID=%s", rsp.ID())
}
