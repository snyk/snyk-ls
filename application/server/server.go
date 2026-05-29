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

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog"
	"github.com/shirou/gopsutil/process"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/codelens"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	scanner2 "github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	noti "github.com/snyk/snyk-ls/internal/notification"
	er "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/progress"
	storage2 "github.com/snyk/snyk-ls/internal/storage"
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
	deps := di.Init(engine, tokenService)
	initHandlers(srv, handlers, conf, engine, logger, deps)

	startLogger.Info().Msg("Starting up Language Server...")
	srv = srv.Start(channel.LSP(os.Stdin, os.Stdout))
	status := srv.WaitStatus()
	if status.Err != nil {
		startLogger.Err(status.Err).Msg("server stopped because of error")
	} else {
		startLogger.Debug().Msgf("server stopped gracefully stopped=%v closed=%v", status.Stopped, status.Closed)
	}
}

// withContext wraps a jrpc2.Handler to inject logger, configuration, engine,
// and all handler dependencies into the context so that handlers can read them
// from ctx rather than reaching for package-level di.* globals.
func withContext(
	h jrpc2.Handler,
	logger *zerolog.Logger,
	conf configuration.Configuration,
	engine workflow.Engine,
	deps di.Dependencies,
) jrpc2.Handler {
	return func(ctx context.Context, req *jrpc2.Request) (any, error) {
		ctx = ctx2.NewContextWithLogger(ctx, logger)
		ctxDeps := make(map[string]any)
		ctxDeps[ctx2.DepConfiguration] = conf
		ctxDeps[ctx2.DepEngine] = engine
		injectCoreServicesIntoMap(ctxDeps, deps)
		injectScanServicesIntoMap(ctxDeps, deps)
		ctx = ctx2.NewContextWithDependencies(ctx, ctxDeps)
		return h(ctx, req)
	}
}

// injectCoreServicesIntoMap and injectScanServicesIntoMap together inject all
// di.Dependencies fields into the context dep map. The split is purely to keep
// each function's cyclomatic complexity below the gocyclo limit (15); it does
// not reflect a semantic boundary between the services.
func injectCoreServicesIntoMap(m map[string]any, deps di.Dependencies) {
	if deps.ConfigResolver != nil {
		m[ctx2.DepConfigResolver] = deps.ConfigResolver
	}
	if deps.AuthenticationService != nil {
		m[ctx2.DepAuthService] = deps.AuthenticationService
	}
	if deps.LdxSyncService != nil {
		m[ctx2.DepLdxSyncService] = deps.LdxSyncService
	}
	if deps.Notifier != nil {
		m[ctx2.DepNotifier] = deps.Notifier
	}
	if deps.InlineValueProvider != nil {
		m[ctx2.DepInlineValueProvider] = deps.InlineValueProvider
	}
	if deps.ErrorReporter != nil {
		m[ctx2.DepErrorReporter] = deps.ErrorReporter
	}
	if deps.CodeActionService != nil {
		m[ctx2.DepCodeActionService] = deps.CodeActionService
	}
	if deps.FeatureFlagService != nil {
		m[ctx2.DepFeatureFlagService] = deps.FeatureFlagService
	}
	if deps.LearnService != nil {
		m[ctx2.DepLearnService] = deps.LearnService
	}
	if deps.FileWatcher != nil {
		m[ctx2.DepFileWatcher] = deps.FileWatcher
	}
	if deps.TreeEmitter != nil {
		m[ctx2.DepTreeEmitter] = deps.TreeEmitter
	}
}

func injectScanServicesIntoMap(m map[string]any, deps di.Dependencies) {
	if deps.Scanner != nil {
		m[ctx2.DepScanners] = deps.Scanner
	}
	if deps.HoverService != nil {
		m[ctx2.DepHoverService] = deps.HoverService
	}
	if deps.ScanPersister != nil {
		m[ctx2.DepScanPersister] = deps.ScanPersister
	}
	if deps.ScanNotifier != nil {
		m[ctx2.DepScanNotifier] = deps.ScanNotifier
	}
	if deps.ScanStateAggregator != nil {
		m[ctx2.DepScanStateAggregator] = deps.ScanStateAggregator
	}
}

const textDocumentDidOpenOperation = "textDocument/didOpen"

const textDocumentDidSaveOperation = "textDocument/didSave"

func initHandlers(srv *jrpc2.Server, handlers handler.Map, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, deps di.Dependencies) {
	enrich := func(h jrpc2.Handler) jrpc2.Handler {
		return withContext(h, logger, conf, engine, deps)
	}
	handlers["initialize"] = enrich(initializeHandler(conf, engine, srv))
	handlers["initialized"] = enrich(initializedHandler(conf, engine, srv))
	handlers["textDocument/didChange"] = enrich(textDocumentDidChangeHandler(conf))
	handlers["textDocument/didClose"] = enrich(noOpHandler())
	handlers[textDocumentDidOpenOperation] = enrich(textDocumentDidOpenHandler(conf))
	handlers[textDocumentDidSaveOperation] = enrich(textDocumentDidSaveHandler(conf))
	handlers["textDocument/hover"] = enrich(textDocumentHover())
	handlers["textDocument/codeAction"] = enrich(textDocumentCodeActionHandler(logger, deps.CodeActionService))
	handlers["textDocument/codeLens"] = enrich(codeLensHandler())
	handlers["textDocument/inlineValue"] = enrich(textDocumentInlineValueHandler())
	handlers["textDocument/willSave"] = enrich(noOpHandler())
	handlers["textDocument/willSaveWaitUntil"] = enrich(noOpHandler())
	handlers["codeAction/resolve"] = enrich(codeActionResolveHandler(logger, deps.CodeActionService, srv))
	handlers["shutdown"] = enrich(shutdownHandler())
	handlers["exit"] = enrich(exitHandler(srv))
	handlers["workspace/didChangeWorkspaceFolders"] = enrich(workspaceDidChangeWorkspaceFoldersHandler(conf, engine, srv))
	handlers["workspace/willDeleteFiles"] = enrich(workspaceWillDeleteFilesHandler(conf))
	handlers["workspace/didChangeConfiguration"] = enrich(workspaceDidChangeConfiguration(conf, srv))
	handlers["window/workDoneProgress/cancel"] = enrich(windowWorkDoneProgressCancelHandler())
	handlers["workspace/executeCommand"] = enrich(executeCommandHandler(srv))
	handlers["$/cancelRequest"] = cancelRequestHandler(srv)
}

func authenticationServiceFromContext(ctx context.Context) (authentication.AuthenticationService, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	authService, ok := deps[ctx2.DepAuthService].(authentication.AuthenticationService)
	return authService, ok
}

func ldxSyncServiceFromContext(ctx context.Context) (command.LdxSyncService, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	ldxSyncService, ok := deps[ctx2.DepLdxSyncService].(command.LdxSyncService)
	return ldxSyncService, ok
}

func mustLdxSyncServiceFromContext(ctx context.Context) command.LdxSyncService {
	ldxSyncService, ok := ldxSyncServiceFromContext(ctx)
	if !ok {
		panic("LDX-Sync service missing from context")
	}
	return ldxSyncService
}

func notifierFromContext(ctx context.Context) (noti.Notifier, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	notifier, ok := deps[ctx2.DepNotifier].(noti.Notifier)
	return notifier, ok
}

func mustNotifierFromContext(ctx context.Context) noti.Notifier {
	notifier, ok := notifierFromContext(ctx)
	if !ok {
		panic("Notifier missing from context")
	}
	return notifier
}

func inlineValueProviderFromContext(ctx context.Context) (snyk.InlineValueProvider, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	p, ok := deps[ctx2.DepInlineValueProvider].(snyk.InlineValueProvider)
	return p, ok
}

func fileWatcherFromContext(ctx context.Context) (*watcher.FileWatcher, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	fw, ok := deps[ctx2.DepFileWatcher].(*watcher.FileWatcher)
	return fw, ok
}

func mustFileWatcherFromContext(ctx context.Context) *watcher.FileWatcher {
	fw, ok := fileWatcherFromContext(ctx)
	if !ok {
		panic("FileWatcher missing from context")
	}
	return fw
}

func errorReporterFromContext(ctx context.Context) (er.ErrorReporter, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	reporter, ok := deps[ctx2.DepErrorReporter].(er.ErrorReporter)
	return reporter, ok
}

func mustErrorReporterFromContext(ctx context.Context) er.ErrorReporter {
	reporter, ok := errorReporterFromContext(ctx)
	if !ok {
		panic("ErrorReporter missing from context")
	}
	return reporter
}

func hoverServiceFromContext(ctx context.Context) (hover.Service, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	svc, ok := deps[ctx2.DepHoverService].(hover.Service)
	return svc, ok
}

func mustHoverServiceFromContext(ctx context.Context) hover.Service {
	svc, ok := hoverServiceFromContext(ctx)
	if !ok {
		panic("HoverService missing from context")
	}
	return svc
}

func scannerFromContext(ctx context.Context) (scanner2.Scanner, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	s, ok := deps[ctx2.DepScanners].(scanner2.Scanner)
	return s, ok
}

func mustScannerFromContext(ctx context.Context) scanner2.Scanner {
	s, ok := scannerFromContext(ctx)
	if !ok {
		panic("Scanner missing from context")
	}
	return s
}

func scanPersisterFromContext(ctx context.Context) (persistence.ScanSnapshotPersister, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	sp, ok := deps[ctx2.DepScanPersister].(persistence.ScanSnapshotPersister)
	return sp, ok
}

func mustScanPersisterFromContext(ctx context.Context) persistence.ScanSnapshotPersister {
	sp, ok := scanPersisterFromContext(ctx)
	if !ok {
		panic("ScanPersister missing from context")
	}
	return sp
}

// scanNotifierFromContext uses the (ok) pattern; addWorkspaceFolders returns an
// error to initializeHandler when the dep is absent.
func scanNotifierFromContext(ctx context.Context) (scanner2.ScanNotifier, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	sn, ok := deps[ctx2.DepScanNotifier].(scanner2.ScanNotifier)
	return sn, ok
}

func featureFlagServiceFromContext(ctx context.Context) (featureflag.Service, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	svc, ok := deps[ctx2.DepFeatureFlagService].(featureflag.Service)
	return svc, ok
}

func mustFeatureFlagServiceFromContext(ctx context.Context) featureflag.Service {
	svc, ok := featureFlagServiceFromContext(ctx)
	if !ok {
		panic("FeatureFlagService missing from context")
	}
	return svc
}

func learnServiceFromContext(ctx context.Context) (learn.Service, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	svc, ok := deps[ctx2.DepLearnService].(learn.Service)
	return svc, ok
}

func mustLearnServiceFromContext(ctx context.Context) learn.Service {
	svc, ok := learnServiceFromContext(ctx)
	if !ok {
		panic("LearnService missing from context")
	}
	return svc
}

func scanStateAggregatorFromContext(ctx context.Context) (scanstates.Aggregator, bool) {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil, false
	}
	agg, ok := deps[ctx2.DepScanStateAggregator].(scanstates.Aggregator)
	return agg, ok
}

func mustScanStateAggregatorFromContext(ctx context.Context) scanstates.Aggregator {
	agg, ok := scanStateAggregatorFromContext(ctx)
	if !ok {
		panic("ScanStateAggregator missing from context")
	}
	return agg
}

func configResolverFromContext(ctx context.Context) (types.ConfigResolverInterface, bool) {
	return ctx2.ConfigResolverFromContext(ctx)
}

func mustConfigResolverFromContext(ctx context.Context) types.ConfigResolverInterface {
	cr, ok := configResolverFromContext(ctx)
	if !ok {
		panic("ConfigResolver missing from context")
	}
	return cr
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

		mustFileWatcherFromContext(ctx).SetFileAsChanged(params.TextDocument.URI)

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

		isDirtyFile := mustFileWatcherFromContext(ctx).IsDirty(params.TextDocument.URI)

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

		// Deps below are injected by withContext if non-nil in DI wiring; each is checked
		// before use below. HandleFolders guards nil featureFlagService internally, and a
		// missing dep here surfaces as a no-op in HandleFolders — acceptable because
		// workspace-folder changes are non-destructive and the handler can be retried.
		authService, _ := authenticationServiceFromContext(ctx)
		notifier := mustNotifierFromContext(ctx)
		ldxSyncSvc, _ := ldxSyncServiceFromContext(ctx)
		scanPersister, _ := scanPersisterFromContext(ctx)
		scanStateAgg, _ := scanStateAggregatorFromContext(ctx)
		featureFlags, _ := featureFlagServiceFromContext(ctx)
		configResolver, _ := ctx2.ConfigResolverFromContext(ctx)

		if authService != nil && authService.IsAuthenticated() && ldxSyncSvc != nil {
			ldxSyncSvc.RefreshConfigFromLdxSync(bgCtx, conf, engine, &logger, changedFolders, notifier)
		}

		command.HandleFolders(conf, engine, &logger, bgCtx, srv, notifier, scanPersister, scanStateAgg, featureFlags, configResolver)
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
		applyConfigFileFromInitializationOptions(conf, params.InitializationOptions)
		file, err := folderconfig.ConfigFileFromConfig(conf)
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

		// Register the OAuth storage bridge before any pre-initialization API
		// call so a rotated refresh token is reliably propagated to the IDE
		// (queued until SettingIsLspInitialized turns true).
		authenticationService, ok := authenticationServiceFromContext(ctx)
		if !ok {
			return nil, errors.New("authentication service missing from request context")
		}
		authentication.RegisterOAuthStorageBridge(storage, authenticationService)

		if err := addWorkspaceFolders(ctx, conf, &logger, engine, params); err != nil {
			return nil, err
		}
		// Prime ORGANIZATION for hot-path GlobalOrg(); see GetGlobalOrganization.
		// Must run before RefreshConfigFromLdxSync and HandleFolders, which rely
		// on the resolver's global-org fallback for folders without a preferred org.
		_ = types.GetGlobalOrganization(conf)
		ldxSyncService, ok := ldxSyncServiceFromContext(ctx)
		if !ok {
			return nil, errors.New("LDX Sync service missing from request context")
		}
		ldxSyncService.RefreshConfigFromLdxSync(ctx, conf, engine, &logger, config.GetWorkspace(conf).Folders(), nil)
		InitializeSettings(ctx, conf, engine, &logger, params.InitializationOptions)

		startClientMonitor(params, logger)

		// NewLspInitializedChannel must precede registerNotifier: the notifier
		// goroutine reads this channel on its first message.
		types.NewLspInitializedChannel(conf)
		go createProgressListener(progress.ToServerProgressChannel, srv, &logger)
		registerNotifier(conf, &logger, srv, mustNotifierFromContext(ctx))

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

func applyConfigFileFromInitializationOptions(conf configuration.Configuration, opts types.InitializationOptions) {
	for _, key := range []string{types.SettingConfigFileLegacy, types.SettingConfigFile} {
		setting, ok := opts.Settings[key]
		if !ok || setting == nil {
			continue
		}
		configFile, ok := setting.Value.(string)
		configFile = strings.TrimSpace(configFile)
		if ok && configFile != "" {
			types.SetGlobalSystemDefault(conf, types.SettingConfigFile, configFile)
			conf.Set(types.SettingConfigFileLegacy, configFile)
			return
		}
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
			types.SignalLspInitialized(conf)
		}()
		configRes := mustConfigResolverFromContext(ctx)
		notifier := mustNotifierFromContext(ctx)

		initialLogger.Info().Msg("snyk-ls: " + config.Version + " (" + util.Result(os.Executable()) + ")")
		cliPath := configRes.GetString(types.SettingCliPath, nil)
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

		handleProtocolVersion(conf, engine, notifier, &logger, config.LsProtocolVersion, configRes.GetString(types.SettingClientProtocolVersion, nil))

		go func() {
			learnService := mustLearnServiceFromContext(ctx)
			_, err := learnService.GetAllLessons()
			if err != nil {
				logger.Err(err).Msg("Error initializing lessons cache")
			}
			go learnService.MaintainCacheFunc()
		}()

		err := mustScannerFromContext(ctx).Init(ctx)
		if err != nil {
			logger.Error().Err(err).Msg("Scan initialization error, canceling scan")
			return nil, nil
		}
		scanPersister := mustScanPersisterFromContext(ctx)
		scanStateAgg := mustScanStateAggregatorFromContext(ctx)
		ffService := mustFeatureFlagServiceFromContext(ctx)
		command.HandleFolders(conf, engine, &logger, context.Background(), srv, notifier, scanPersister, scanStateAgg, ffService, configRes)

		deleteExpiredCache(conf)
		cacheCtx, cancel := context.WithCancel(context.Background())
		cacheCheckCancel = cancel
		go periodicallyCheckForExpiredCache(cacheCtx, conf)

		autoScanEnabled := configRes.GetBool(types.SettingScanAutomatic, nil)
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

func startOfflineDetection(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, configRes types.ConfigResolverInterface, notifier noti.Notifier) { //nolint:unused // this is gonna be used soon
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
				if !configRes.GetBool(types.SettingOffline, nil) {
					msg := fmt.Sprintf("Cannot connect to %s. You need to fix your networking for Snyk to work.", u)
					reportedErr := errors.Join(err, errors.New(msg))
					logger.Err(reportedErr).Send()
					notifier.SendShowMessage(sglsp.Warning, msg)
				}
				types.SetGlobalSystemDefault(conf, types.SettingOffline, true)
			} else {
				if configRes.GetBool(types.SettingOffline, nil) {
					msg := fmt.Sprintf("Snyk is active again. We were able to reach %s", u)
					notifier.SendShowMessage(sglsp.Info, msg)
					logger.Info().Msg(msg)
				}
				types.SetGlobalSystemDefault(conf, types.SettingOffline, false)
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

func addWorkspaceFolders(ctx context.Context, conf configuration.Configuration, logger *zerolog.Logger, engine workflow.Engine, params types.InitializeParams) error {
	const method = "addWorkspaceFolders"
	w := config.GetWorkspace(conf)

	scn, scnOk := scannerFromContext(ctx)
	hs, hsOk := hoverServiceFromContext(ctx)
	scanNotifier, snOk := scanNotifierFromContext(ctx)
	notifier, nOk := notifierFromContext(ctx)
	scanPersister, spOk := scanPersisterFromContext(ctx)
	scanStateAgg, ssaOk := scanStateAggregatorFromContext(ctx)
	featureFlags, ffOk := featureFlagServiceFromContext(ctx)
	configResolver, crOk := ctx2.ConfigResolverFromContext(ctx)
	if !scnOk || !hsOk || !snOk || !nOk || !spOk || !ssaOk || !ffOk || !crOk {
		logger.Error().Str("method", method).
			Bool("scanner", scnOk).
			Bool("hoverService", hsOk).
			Bool("scanNotifier", snOk).
			Bool("notifier", nOk).
			Bool("scanPersister", spOk).
			Bool("scanStateAggregator", ssaOk).
			Bool("featureFlagService", ffOk).
			Bool("configResolver", crOk).
			Msg("missing mandatory dependency in context; LSP initialize will fail")
		return errors.New("snyk-ls: missing mandatory DI dependency at initialize")
	}

	newFolder := func(path types.FilePath, name string) *workspace.Folder {
		return workspace.NewFolder(conf, logger, path, name, scn, hs, scanNotifier, notifier, scanPersister, scanStateAgg, featureFlags, configResolver, engine)
	}

	if len(params.WorkspaceFolders) > 0 {
		for _, workspaceFolder := range params.WorkspaceFolders {
			logger.Info().Str("method", method).Msgf("Adding workspaceFolder %v", workspaceFolder)
			w.AddFolder(newFolder(types.PathKey(uri.PathFromUri(workspaceFolder.Uri)), workspaceFolder.Name))
		}
	} else {
		if params.RootURI != "" {
			w.AddFolder(newFolder(types.PathKey(uri.PathFromUri(params.RootURI)), params.ClientInfo.Name))
		} else if params.RootPath != "" {
			w.AddFolder(newFolder(types.FilePath(params.RootPath), params.ClientInfo.Name))
		}
	}
	return nil
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
		mustErrorReporterFromContext(ctx).FlushErrorReporting()

		if cacheCheckCancel != nil {
			cacheCheckCancel()
		}
		di.DisposeTreeEmitter()
		disposeProgressListener()
		mustNotifierFromContext(ctx).DisposeListener()
		command.StopPendingRescanTimers()
		return nil, nil
	})
}

func exitHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context) (any, error) {
		logger := ctx2.LoggerFromContext(ctx).With().Str("method", "Exit").Logger()
		logger.Info().Msg("ENTERING")
		logger.Info().Msg("Flushing error reporting...")
		mustErrorReporterFromContext(ctx).FlushErrorReporting()
		logger.Info().Msg("Stopping server...")
		srv.Stop()
		return nil, nil
	})
}

func logError(logger *zerolog.Logger, reporter er.ErrorReporter, err error, method string) {
	if err != nil {
		logger.Err(err).Str("method", method)
		if reporter != nil {
			reporter.CaptureError(err)
		}
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
			mustNotifierFromContext(ctx).Send(diagnosticParams)
		}

		return nil, nil
	})
}

func textDocumentDidSaveHandler(conf configuration.Configuration) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidSaveTextDocumentParams) (any, error) {
		bgCtx := context.Background()
		logger := ctx2.LoggerFromContext(ctx).With().Str("method", "TextDocumentDidSaveHandler").Logger()
		logger.Debug().Interface("params", params).Msg("Receiving")

		mustFileWatcherFromContext(ctx).SetFileAsSaved(params.TextDocument.URI)
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
		hoverResult := mustHoverServiceFromContext(ctx).GetHover(pathFromUri, converter.FromPosition(params.Position))
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

func codeActionResolveHandler(logger *zerolog.Logger, svc *codeaction.CodeActionsService, server types.Server) handler.Func {
	return handler.New(ResolveCodeActionHandler(logger, svc, server))
}

func textDocumentCodeActionHandler(logger *zerolog.Logger, svc *codeaction.CodeActionsService) handler.Func {
	return handler.New(GetCodeActionHandler(logger, svc))
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
