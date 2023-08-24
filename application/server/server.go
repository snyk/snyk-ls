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
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/process"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/go-application-framework/pkg/networking"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/codelens"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
)

func Start(c *config.Config) {
	var srv *jrpc2.Server

	handlers := handler.Map{}
	srv = jrpc2.NewServer(handlers, &jrpc2.ServerOptions{
		Logger: func(text string) {
			if zerolog.GlobalLevel() == zerolog.TraceLevel {
				if len(text) > 300 {
					// this may not be sent to the logger, as it would produce a loop, therefore we write to stderr
					_, _ = os.Stderr.WriteString(fmt.Sprintf("JSON RPC Log: %s... [TRUNCATED]", text[:300]))
				} else {
					_, _ = os.Stderr.WriteString(fmt.Sprintf("JSON RPC Log: %s", text))
				}
			}
		},
		RPCLog:    RPCLogger{},
		AllowPush: true,
	})

	c.ConfigureLogging(srv)
	di.Init()
	initHandlers(c, srv, handlers)

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

const textDocumentDidOpenOperation = "textDocument/didOpen"
const textDocumentDidSaveOperation = "textDocument/didSave"

func initHandlers(c *config.Config, srv *jrpc2.Server, handlers handler.Map) {
	handlers["initialize"] = initializeHandler(srv, c)
	handlers["initialized"] = initializedHandler(srv)
	handlers["textDocument/didChange"] = textDocumentDidChangeHandler()
	handlers["textDocument/didClose"] = noOpHandler()
	handlers[textDocumentDidOpenOperation] = textDocumentDidOpenHandler()
	handlers[textDocumentDidSaveOperation] = textDocumentDidSaveHandler()
	handlers["textDocument/hover"] = textDocumentHover()
	handlers["textDocument/codeAction"] = textDocumentCodeActionHandler(c)
	handlers["textDocument/codeLens"] = codeLensHandler()
	handlers["textDocument/inlineValue"] = textDocumentInlineValueHandler(c)
	handlers["textDocument/willSave"] = noOpHandler()
	handlers["textDocument/willSaveWaitUntil"] = noOpHandler()
	handlers["codeAction/resolve"] = codeActionResolveHandler(c, srv, di.AuthenticationService(), di.LearnService())
	handlers["shutdown"] = shutdown()
	handlers["exit"] = exit(srv)
	handlers["workspace/didChangeWorkspaceFolders"] = workspaceDidChangeWorkspaceFoldersHandler(srv)
	handlers["workspace/willDeleteFiles"] = workspaceWillDeleteFilesHandler()
	handlers["workspace/didChangeConfiguration"] = workspaceDidChangeConfiguration(srv)
	handlers["window/workDoneProgress/cancel"] = windowWorkDoneProgressCancelHandler()
	handlers["workspace/executeCommand"] = executeCommandHandler(srv)
}

func textDocumentDidChangeHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidChangeTextDocumentParams) (any, error) {
		di.FileWatcher().SetFileAsChanged(params.TextDocument.URI)
		return nil, nil
	})
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

func codeLensHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.CodeLensParams) ([]sglsp.CodeLens, error) {
		log.Info().Str("method", "CodeLensHandler").Msg("RECEIVING")
		defer log.Info().Str("method", "CodeLensHandler").Msg("SENDING")

		lenses := codelens.GetFor(uri.PathFromUri(params.TextDocument.URI))

		// Do not return Snyk Code Fix codelens when a doc is dirty
		isDirtyFile := di.FileWatcher().IsDirty(params.TextDocument.URI)
		if !isDirtyFile {
			return lenses, nil
		}

		return filterCodeFixCodelens(lenses), nil
	})
}

func filterCodeFixCodelens(lenses []sglsp.CodeLens) []sglsp.CodeLens {
	var filteredLenses []sglsp.CodeLens
	for _, lense := range lenses {
		if lense.Command.Command == snyk.CodeFixCommand {
			continue
		}

		filteredLenses = append(filteredLenses, lense)
	}
	return filteredLenses
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
		command.HandleUntrustedFolders(bgCtx, srv)
		return nil, nil
	})
}

func initNetworkAccessHeaders() {
	engine := config.CurrentConfig().Engine()
	ua := networking.UserAgent(networking.UaWithConfig(engine.GetConfiguration()), networking.UaWithApplication("snyk-ls", config.Version))
	engine.GetNetworkAccess().AddHeaderField("User-Agent", ua.String())
}

func initializeHandler(srv *jrpc2.Server, c *config.Config) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializeParams) (any, error) {
		method := "initializeHandler"
		log.Info().Str("method", method).Any("params", params).Msg("RECEIVING")
		InitializeSettings(params.InitializationOptions)
		config.CurrentConfig().SetClientCapabilities(params.Capabilities)
		setClientInformation(params)
		di.Analytics().Initialise()

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

		addWorkspaceFolders(params, workspace.Get())

		result := lsp.InitializeResult{
			ServerInfo: lsp.ServerInfo{
				Name:    "snyk-ls",
				Version: config.LsProtocolVersion,
			},
			Capabilities: lsp.ServerCapabilities{
				TextDocumentSync: &sglsp.TextDocumentSyncOptionsOrKind{
					Options: &sglsp.TextDocumentSyncOptions{
						OpenClose:         true,
						Change:            sglsp.TDSKIncremental,
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
				HoverProvider:       true,
				CodeActionProvider:  &lsp.CodeActionOptions{ResolveProvider: true},
				CodeLensProvider:    &sglsp.CodeLensOptions{ResolveProvider: false},
				InlineValueProvider: true,
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
						snyk.OpenLearnLesson,
						snyk.GetLearnLesson,
						snyk.GetSettingsSastEnabled,
						snyk.GetActiveUserCommand,
						snyk.CodeFixCommand,
						snyk.CodeSubmitFixFeedback,
					},
				},
			},
		}
		log.Debug().Str("method", method).Any("result", result).Msg("SENDING")
		return result, nil
	})
}
func initializedHandler(srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializedParams) (any, error) {
		// Logging these messages only after the client has been initialized.
		// Logging to the client is only allowed after the client has been initialized according to LSP protocol.
		// No reason to log the method name for these messages, because some of these values are empty and the messages
		// looks weird when including the method name.
		c := config.CurrentConfig()
		log.Info().Msg("snyk-ls: " + config.Version + " (" + util.Result(os.Executable()) + ")")
		log.Info().Msg("platform: " + runtime.GOOS + "/" + runtime.GOARCH)
		log.Info().Msg("https_proxy: " + os.Getenv("HTTPS_PROXY"))
		log.Info().Msg("http_proxy: " + os.Getenv("HTTP_PROXY"))
		log.Info().Msg("no_proxy: " + os.Getenv("NO_PROXY"))
		log.Info().Msg("IDE: " + c.IdeName() + "/" + c.IdeVersion())
		log.Info().Msg("snyk-plugin: " + c.IntegrationName() + "/" + c.IntegrationVersion())
		logger := log.With().Str("method", "initializedHandler").Logger()
		// CLI & Authentication initialization
		err := di.Scanner().Init()
		if err != nil {
			log.Error().Err(err).Msg("Scan initialization error, cancelling scan")
			return nil, err
		}

		authenticated, err := di.AuthenticationService().IsAuthenticated()
		if err != nil {
			logger.Error().Err(err).Msg("Not authenticated, or error checking authentication status")
		}

		autoScanEnabled := config.CurrentConfig().IsAutoScanEnabled()
		if autoScanEnabled && authenticated {
			logger.Debug().Msg("triggering workspace scan after successful initialization")
			workspace.Get().ScanWorkspace(context.Background())
		} else {
			logger.Debug().Msg("No automatic workspace scan on initialization - auto-scan is disabled")
		}

		if config.CurrentConfig().AutomaticAuthentication() || config.CurrentConfig().NonEmptyToken() {
			logger.Debug().Msg("trying to get trusted status for untrusted folders")
			go command.HandleUntrustedFolders(context.Background(), srv)
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
				di.ScanNotifier(),
				di.Notifier(),
			)
			w.AddFolder(f)
		}
	} else {
		if params.RootURI != "" {
			f := workspace.NewFolder(uri.PathFromUri(params.RootURI),
				params.ClientInfo.Name,
				di.Scanner(),
				di.HoverService(),
				di.ScanNotifier(),
				di.Notifier())
			w.AddFolder(f)
		} else if params.RootPath != "" {
			f := workspace.NewFolder(params.RootPath,
				params.ClientInfo.Name,
				di.Scanner(),
				di.HoverService(),
				di.ScanNotifier(),
				di.Notifier())
			w.AddFolder(f)
		}
	}
}

// setClientInformation sets the integration name and version from the client information.
// The integration version refers to the plugin version, not the IDE version.
// The function attempts to pull the values from the initialization options, then the client info, and finally
// from the environment variables.
func setClientInformation(initParams lsp.InitializeParams) {
	var integrationName, integrationVersion string
	if initParams.InitializationOptions.IntegrationName != "" {
		integrationName = initParams.InitializationOptions.IntegrationName
		integrationVersion = initParams.InitializationOptions.IntegrationVersion
	} else if initParams.ClientInfo.Name != "" {
		integrationName = strings.ToUpper(strings.Replace(initParams.ClientInfo.Name, " ", "_", -1))
	} else if integrationNameEnvVar := os.Getenv(cli.IntegrationNameEnvVarKey); integrationNameEnvVar != "" {
		integrationName = integrationNameEnvVar
		integrationVersion = os.Getenv(cli.IntegrationVersionEnvVarKey)
	} else {
		return
	}

	c := config.CurrentConfig()
	c.SetIntegrationName(integrationName)
	c.SetIntegrationVersion(integrationVersion)
	c.SetIdeName(initParams.ClientInfo.Name)
	c.SetIdeVersion(initParams.ClientInfo.Version)

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
		log.Info().Str("method", "Shutdown").Msg("RECEIVING")
		defer log.Info().Str("method", "Shutdown").Msg("SENDING")
		di.ErrorReporter().FlushErrorReporting()

		disposeProgressListener()
		di.Notifier().DisposeListener()
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
		if folder == nil {
			logger.Warn().Msg("No folder found for file " + filePath)
			return nil, nil
		}

		issues := folder.DocumentDiagnosticsFromCache(filePath)
		filteredIssues := workspace.FilterIssues(issues, config.CurrentConfig().DisplayableIssueTypes())

		if len(filteredIssues) > 0 {
			logger.Info().Msg("Sending cached issues")
			diagnosticParams := lsp.PublishDiagnosticsParams{
				URI:         params.TextDocument.URI,
				Diagnostics: converter.ToDiagnostics(filteredIssues),
			}
			di.Notifier().Send(diagnosticParams)
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
		di.FileWatcher().SetFileAsSaved(params.TextDocument.URI)
		filePath := uri.PathFromUri(params.TextDocument.URI)

		// todo can we push cache management down?
		f := workspace.Get().GetFolderContaining(filePath)
		autoScanEnabled := config.CurrentConfig().IsAutoScanEnabled()
		if f != nil {
			f.ClearDiagnosticsFromFile(filePath)
			di.HoverService().DeleteHover(params.TextDocument.URI)

			if autoScanEnabled {
				go f.ScanFile(bgCtx, filePath)
			}
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

func codeActionResolveHandler(c *config.Config,
	server lsp.Server,
	authenticationService snyk.AuthenticationService,
	learnService learn.Service,
) handler.Func {
	return handler.New(codeaction.ResolveCodeActionHandler(c,
		di.CodeActionService(),
		server,
		authenticationService,
		learnService))
}

func textDocumentCodeActionHandler(c *config.Config) handler.Func {
	return handler.New(codeaction.GetCodeActionHandler(c, di.CodeActionService()))
}

func noOpHandler() jrpc2.Handler {
	return handler.New(func(_ context.Context, params sglsp.DidCloseTextDocumentParams) (any, error) {
		log.Info().Str("method", "NoOpHandler").Interface("params", params).Msg("RECEIVING")
		return nil, nil
	})
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
