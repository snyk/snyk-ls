/*
 * © 2022 Snyk Limited All rights reserved.
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
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/process"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/codeaction"
	"github.com/snyk/snyk-ls/domain/ide/codelens"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Start() {
	log.Debug().Msg("Starting server...")
	var srv *jrpc2.Server

	handlers := handler.Map{}
	srv = jrpc2.NewServer(handlers, &jrpc2.ServerOptions{
		Logger: func(text string) {
			if len(text) > 300 {
				log.Debug().Msgf("JSON RPC Log: %s... [TRUNCATED]", text[:300])
			} else {
				log.Debug().Msgf("JSON RPC Log: %s", text)
			}
		},
		RPCLog:    RPCLogger{},
		AllowPush: true,
	})
	initHandlers(srv, &handlers)

	log.Info().Msg("Starting up...")
	srv = srv.Start(channel.Header("")(os.Stdin, os.Stdout))

	status := srv.WaitStatus()
	if status.Err != nil {
		log.Err(status.Err).Msg("server stopped because of error")
	} else {
		log.Debug().Msgf("server stopped gracefully stopped=%v closed=%v", status.Stopped, status.Closed)
	}
	log.Info().Msg("Exiting...")
}

func initHandlers(srv *jrpc2.Server, handlers *handler.Map) {
	(*handlers)["initialize"] = initializeHandler(srv)
	(*handlers)["initialized"] = initializedHandler(srv)
	(*handlers)["textDocument/didOpen"] = textDocumentDidOpenHandler()
	(*handlers)["textDocument/didChange"] = noOpHandler()
	(*handlers)["textDocument/didClose"] = noOpHandler()
	(*handlers)["textDocument/didSave"] = textDocumentDidSaveHandler()
	(*handlers)["textDocument/hover"] = textDocumentHover()
	(*handlers)["textDocument/codeAction"] = codeActionHandler()
	(*handlers)["textDocument/codeLens"] = codeLensHandler()
	(*handlers)["textDocument/willSave"] = noOpHandler()
	(*handlers)["textDocument/willSaveWaitUntil"] = noOpHandler()
	(*handlers)["shutdown"] = shutdown()
	(*handlers)["exit"] = exit(srv)
	(*handlers)["workspace/didChangeWorkspaceFolders"] = workspaceDidChangeWorkspaceFoldersHandler(srv)
	(*handlers)["workspace/willDeleteFiles"] = workspaceWillDeleteFilesHandler()
	(*handlers)["workspace/didChangeConfiguration"] = workspaceDidChangeConfiguration(srv)
	(*handlers)["window/workDoneProgress/cancel"] = windowWorkDoneProgressCancelHandler()
	(*handlers)["workspace/executeCommand"] = executeCommandHandler(srv)
}

// WorkspaceWillDeleteFilesHandler handles the workspace/willDeleteFiles message that's raised by the client
// when files are deleted
func workspaceWillDeleteFilesHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DeleteFilesParams) (any, error) {
		ws := workspace.Get()
		for _, file := range params.Files {
			path := uri.PathFromUri(file.Uri)

			// Instead of branching whether it's a file or a folder, we'll attempt to remove both and the redundant case
			// will be a no-op
			ws.RemoveFolder(path)
			ws.DeleteFile(path)
		}
		return nil, nil
	})
}

func navigateToLocation(srv *jrpc2.Server, args []any) {
	method := "navigateToLocation"
	// convert to correct type
	var myRange snyk.Range
	marshal, err := json.Marshal(args[1])
	if err != nil {
		log.Err(errors.Wrap(err, "couldn't marshal range to json")).Str("method", method).Send()
	}
	err = json.Unmarshal(marshal, &myRange)
	if err != nil {
		log.Err(errors.Wrap(err, "couldn't unmarshal range from json")).Str("method", method).Send()
	}

	params := lsp.ShowDocumentParams{
		Uri:       uri.PathToUri(args[0].(string)),
		External:  false,
		TakeFocus: true,
		Selection: converter.ToRange(myRange),
	}
	log.Info().
		Str("method", "navigateToLocation").
		Interface("params", params).
		Msg("showing Document")
	rsp, err := srv.Callback(context.Background(), "window/showDocument", params)
	log.Debug().Str("method", method).Interface("callback", rsp).Send()
	if err != nil {
		logError(err, "navigateToLocation")
	}
}

func codeLensHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.CodeLensParams) ([]sglsp.CodeLens, error) {
		log.Info().Str("method", "CodeLensHandler").Msg("RECEIVING")
		defer log.Info().Str("method", "CodeLensHandler").Msg("SENDING")

		lenses := codelens.GetFor(uri.PathFromUri(params.TextDocument.URI))
		return lenses, nil
	})
}

func codeActionHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.CodeActionParams) ([]lsp.CodeAction, error) {
		log.Info().Str("method", "CodeActionHandler").Interface("action", params).Msg("RECEIVING")
		defer log.Info().Str("method", "CodeActionHandler").Interface("action", params).Msg("SENDING")
		actions := codeaction.GetFor(uri.PathFromUri(params.TextDocument.URI), params.Range)
		return actions, nil
	})
}

func workspaceDidChangeWorkspaceFoldersHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeWorkspaceFoldersParams) (any, error) {
		// The context provided by the JSON-RPC server is cancelled once a new message is being processed,
		// so we don't want to propagate it to functions that start background operations
		bgCtx := context.Background()
		logger := log.With().Str("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Logger()

		logger.Info().Msg("RECEIVING")
		defer logger.Info().Msg("SENDING")
		workspace.Get().ChangeWorkspaceFolders(bgCtx, params)
		handleUntrustedFolders(bgCtx, srv)
		return nil, nil
	})
}

func initializeHandler(srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializeParams) (any, error) {
		method := "initializeHandler"
		log.Info().Str("method", method).Interface("params", params).Msg("RECEIVING")
		InitializeSettings(params.InitializationOptions)
		config.CurrentConfig().SetClientCapabilities(params.Capabilities)
		setClientInformation(params)
		di.Analytics().Initialise()
		w := workspace.New(di.Instrumentor(), di.Scanner(), di.HoverService())
		workspace.Set(w)

		// async processing listener
		go createProgressListener(progress.Channel, srv)
		registerNotifier(srv)
		go func() {
			if params.ProcessID == 0 {
				// if started on its own, no need to exit or to monitor
				return
			}

			monitorClientProcess(params.ProcessID)
			log.Info().Msgf("Shutting down as client pid %d not running anymore.", params.ProcessID)
			os.Exit(0)
		}()

		addWorkspaceFolders(params, w)

		result := lsp.InitializeResult{
			ServerInfo: lsp.ServerInfo{
				Name:    "snyk-ls",
				Version: config.LsProtocolVersion,
			},
			Capabilities: lsp.ServerCapabilities{
				TextDocumentSync: &sglsp.TextDocumentSyncOptionsOrKind{
					Options: &sglsp.TextDocumentSyncOptions{
						OpenClose:         true,
						WillSave:          true,
						WillSaveWaitUntil: true,
						Save:              &sglsp.SaveOptions{IncludeText: true},
					},
				},
				Workspace: &lsp.Workspace{
					WorkspaceFolders: &lsp.WorkspaceFoldersServerCapabilities{
						Supported:           true,
						ChangeNotifications: "snyk-ls",
					},
					FileOperations: &lsp.FileOperationsServerCapabilities{
						WillDelete: lsp.FileOperationRegistrationOptions{
							Filters: []lsp.FileOperationFilter{
								{
									Pattern: lsp.FileOperationPattern{
										Glob: "**",
									},
								},
							},
						},
					},
				},
				HoverProvider:      true,
				CodeActionProvider: true,
				CodeLensProvider:   &sglsp.CodeLensOptions{ResolveProvider: false},
				ExecuteCommandProvider: &sglsp.ExecuteCommandOptions{
					Commands: []string{
						snyk.NavigateToRangeCommand,
						snyk.WorkspaceScanCommand,
						snyk.WorkspaceFolderScanCommand,
						snyk.OpenBrowserCommand,
						snyk.LoginCommand,
						snyk.CopyAuthLinkCommand,
						snyk.LogoutCommand,
						snyk.TrustWorkspaceFoldersCommand,
					},
				},
			},
		}
		return result, nil
	})
}
func initializedHandler(srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializedParams) (any, error) {
		logger := log.With().Str("method", "initializedHandler").Logger()

		logger.Debug().Msg("initializing CLI now")
		err := di.CliInitializer().Init()
		if err != nil {
			di.ErrorReporter().CaptureError(err)
		}
		autoScanEnabled := config.CurrentConfig().IsAutoScanEnabled()
		if autoScanEnabled {
			logger.Debug().Msg("triggering workspace scan after successful initialization")
			workspace.Get().ScanWorkspace(context.Background())
		} else {
			logger.Debug().Msg("No automatic workspace scan on initialization - auto-scan is disabled")
		}

		if config.CurrentConfig().AutomaticAuthentication() || config.CurrentConfig().NonEmptyToken() {
			logger.Debug().Msg("trying to get trusted status for untrusted folders")
			go handleUntrustedFolders(context.Background(), srv)
		}
		return nil, nil
	})
}

func addWorkspaceFolders(params lsp.InitializeParams, w *workspace.Workspace) {
	const method = "addWorkspaceFolders"
	if len(params.WorkspaceFolders) > 0 {
		for _, workspaceFolder := range params.WorkspaceFolders {
			log.Info().Str("method", method).Msgf("Adding workspaceFolder %v", workspaceFolder)
			f := workspace.NewFolder(
				uri.PathFromUri(workspaceFolder.Uri),
				workspaceFolder.Name,
				di.Scanner(),
				di.HoverService(),
			)
			w.AddFolder(f)
		}
	} else {
		if params.RootURI != "" {
			f := workspace.NewFolder(uri.PathFromUri(params.RootURI), params.ClientInfo.Name, di.Scanner(), di.HoverService())
			w.AddFolder(f)
		} else if params.RootPath != "" {
			f := workspace.NewFolder(params.RootPath, params.ClientInfo.Name, di.Scanner(), di.HoverService())
			w.AddFolder(f)
		}
	}
}

func setClientInformation(initParams lsp.InitializeParams) {
	var integrationName, integrationVersion string
	if initParams.InitializationOptions.IntegrationName != "" {
		integrationName = initParams.InitializationOptions.IntegrationName
		integrationVersion = initParams.InitializationOptions.IntegrationVersion
	} else if initParams.ClientInfo.Name != "" {
		integrationName = strings.ToUpper(strings.Replace(initParams.ClientInfo.Name, " ", "_", -1))
		integrationVersion = initParams.ClientInfo.Version
	} else if integrationNameEnvVar := os.Getenv("SNYK_INTEGRATION_NAME"); integrationNameEnvVar != "" {
		integrationName = integrationNameEnvVar
		integrationVersion = os.Getenv("SNYK_INTEGRATION_VERSION")
	} else {
		return
	}

	config.CurrentConfig().SetIntegrationName(integrationName)
	config.CurrentConfig().SetIntegrationVersion(integrationVersion)
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
		log.Info().Str("method", "Shutdown").Msg("RECEIVING")
		defer log.Info().Str("method", "Shutdown").Msg("SENDING")
		di.ErrorReporter().FlushErrorReporting()

		disposeProgressListener()
		notification.DisposeListener()
		err := di.Analytics().Shutdown()
		if err != nil {
			log.Error().Str("method", "Shutdown").Msg("Failed to shutdown analytics.")
		}
		return nil, nil
	})
}

func exit(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(_ context.Context) (any, error) {
		log.Info().Str("method", "Exit").Msg("RECEIVING")
		log.Info().Msg("Stopping server...")
		(*srv).Stop()
		di.ErrorReporter().FlushErrorReporting()
		return nil, nil
	})
}

func logError(err error, method string) {
	if err != nil {
		log.Err(err).Str("method", method)
		di.ErrorReporter().CaptureError(err)
	}
}

func textDocumentDidOpenHandler() jrpc2.Handler {
	return handler.New(func(_ context.Context, params sglsp.DidOpenTextDocumentParams) (any, error) {
		filePath := uri.PathFromUri(params.TextDocument.URI)
		logger := log.With().Str("method", "TextDocumentDidOpenHandler").Str("documentURI", filePath).Logger()

		logger.Info().Msg("Receiving")
		folder := workspace.Get().GetFolderContaining(filePath)
		autoScanEnabled := config.CurrentConfig().IsAutoScanEnabled()
		if folder != nil && autoScanEnabled {
			go folder.ScanFile(context.Background(), filePath)
		} else {
			if autoScanEnabled {
				logger.Warn().Msg("Not scanning, file not part of workspace")
			} else {
				logger.Warn().Msg("Not scanning, auto-scan is disabled")
			}
		}
		return nil, nil
	})
}

func textDocumentDidSaveHandler() jrpc2.Handler {
	return handler.New(func(_ context.Context, params sglsp.DidSaveTextDocumentParams) (any, error) {
		// The context provided by the JSON-RPC server is cancelled once a new message is being processed,
		// so we don't want to propagate it to functions that start background operations
		bgCtx := context.Background()
		logger := log.With().Str("method", "TextDocumentDidSaveHandler").Logger()

		logger.Info().Interface("params", params).Msg("Receiving")
		filePath := uri.PathFromUri(params.TextDocument.URI)

		// todo can we push cache management down?
		f := workspace.Get().GetFolderContaining(filePath)
		autoScanEnabled := config.CurrentConfig().IsAutoScanEnabled()
		if f != nil && autoScanEnabled {
			f.ClearDiagnosticsFromFile(filePath)
			di.HoverService().DeleteHover(params.TextDocument.URI)
			go f.ScanFile(bgCtx, filePath)
		} else {
			if autoScanEnabled {
				logger.Warn().Str("documentURI", filePath).Msg("Not scanning, file not part of workspace")
			} else {
				logger.Warn().Msg("Not scanning, auto-scan is disabled")
			}
		}
		return nil, nil
	})
}

func textDocumentHover() jrpc2.Handler {
	return handler.New(func(_ context.Context, params hover.Params) (hover.Result, error) {
		log.Info().Str("method", "TextDocumentHover").Interface("params", params).Msg("RECEIVING")

		hoverResult := di.HoverService().GetHover(params.TextDocument.URI, converter.FromPosition(params.Position))
		return hoverResult, nil
	})
}

func windowWorkDoneProgressCancelHandler() jrpc2.Handler {
	return handler.New(func(_ context.Context, params lsp.WorkdoneProgressCancelParams) (any, error) {
		log.Info().Str("method", "WindowWorkDoneProgressCancelHandler").Interface("params", params).Msg("RECEIVING")
		CancelProgress(params.Token)
		return nil, nil
	})
}

func noOpHandler() jrpc2.Handler {
	return handler.New(func(_ context.Context, params sglsp.DidCloseTextDocumentParams) (any, error) {
		log.Info().Str("method", "NoOpHandler").Interface("params", params).Msg("RECEIVING")
		return nil, nil
	})
}

func registerNotifier(srv *jrpc2.Server) {
	callbackFunction := func(params any) {
		switch params := params.(type) {
		case lsp.AuthenticationParams:
			notifier(srv, "$/snyk.hasAuthenticated", params)
			log.Info().Str("method", "registerNotifier").
				Msg("sending token")
		case lsp.SnykIsAvailableCli:
			notifier(srv, "$/snyk.isAvailableCli", params)
			log.Info().Str("method", "registerNotifier").
				Msg("sending cli path")
		case sglsp.ShowMessageParams:
			notifier(srv, "window/showMessage", params)
			log.Info().
				Str("method", "registerNotifier").
				Interface("message", params).
				Msg("showing message")
		case lsp.PublishDiagnosticsParams:
			notifier(srv, "textDocument/publishDiagnostics", params)
			source := "LSP"
			if len(params.Diagnostics) > 0 {
				source = params.Diagnostics[0].Source
			}
			log.Info().
				Str("method", "registerNotifier").
				Interface("documentURI", params.URI).
				Interface("source", source).
				Interface("diagnosticCount", len(params.Diagnostics)).
				Msg("publishing diagnostics")
		case lsp.SnykTrustedFoldersParams:
			notifier(srv, "$/snyk.addTrustedFolders", params)
			log.Info().
				Str("method", "registerNotifier").
				Interface("trustedPaths", params.TrustedFolders).
				Msg("sending trusted Folders to client")
		case lsp.SnykScanParams:
			notifier(srv, "$/snyk.scan", params)
			log.Info().
				Str("method", "registerNotifier").
				Interface("product", params.Product).
				Interface("status", params.Status).
				Msg("sending scan data to client")
		default:
			log.Warn().
				Str("method", "registerNotifier").
				Interface("params", params).
				Msg("received unconfigured notification object")
		}
	}
	notification.CreateListener(callbackFunction)
	log.Info().Str("method", "registerNotifier").Msg("registered notifier")
}

type RPCLogger struct{}

func (R RPCLogger) LogRequest(_ context.Context, req *jrpc2.Request) {
	log.Debug().Msgf("Incoming JSON-RPC request. Method=%s. ID=%s. Is notification=%v.",
		req.Method(),
		req.ID(),
		req.IsNotification())
	log.Trace().Str("params", req.ParamString()).Msgf("Incoming JSON-RPC request. Method=%s. ID=%s. Is notification=%v.",
		req.Method(),
		req.ID(),
		req.IsNotification())
}

func (R RPCLogger) LogResponse(_ context.Context, rsp *jrpc2.Response) {
	if rsp.Error() != nil {
		log.Err(rsp.Error()).Interface("rsp", *rsp).Msg("Outgoing JSON-RPC response error")
	}
	log.Debug().Msgf("Outgoing JSON-RPC response. ID=%s", rsp.ID())
}
