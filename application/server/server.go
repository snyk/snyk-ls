package server

import (
	"context"
	"os"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/process"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
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
	di.Init()

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
	(*handlers)["initialize"] = InitializeHandler(srv)
	(*handlers)["textDocument/didOpen"] = TextDocumentDidOpenHandler()
	(*handlers)["textDocument/didChange"] = NoOpHandler()
	(*handlers)["textDocument/didClose"] = NoOpHandler()
	(*handlers)["textDocument/didSave"] = TextDocumentDidSaveHandler()
	(*handlers)["textDocument/hover"] = TextDocumentHover()
	(*handlers)["textDocument/codeAction"] = CodeAction()
	(*handlers)["textDocument/codeLens"] = CodeLensHandler()
	(*handlers)["textDocument/willSave"] = NoOpHandler()
	(*handlers)["textDocument/willSaveWaitUntil"] = NoOpHandler()
	(*handlers)["shutdown"] = Shutdown()
	(*handlers)["exit"] = Exit(srv)
	(*handlers)["workspace/didChangeWorkspaceFolders"] = WorkspaceDidChangeWorkspaceFoldersHandler()
	(*handlers)["workspace/didChangeConfiguration"] = WorkspaceDidChangeConfiguration()
	(*handlers)["window/workDoneProgress/cancel"] = WindowWorkDoneProgressCancelHandler()
}

func CodeLensHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.CodeLensParams) ([]sglsp.CodeLens, error) {
		log.Info().Str("method", "CodeLensHandler").Msg("RECEIVING")
		defer log.Info().Str("method", "CodeLensHandler").Msg("SENDING")

		filePath := uri.PathFromUri(params.TextDocument.URI)
		f := workspace.Get().GetFolderContaining(filePath)
		if f != nil {
			issues := f.DocumentDiagnosticsFromCache(filePath)
			var lenses []sglsp.CodeLens
			for _, issue := range issues {
				for _, command := range issue.Commands {
					lenses = append(lenses, getCodeLensFromCommand(issue, command))
				}
			}
			return lenses, nil
		}
		return nil, nil
	})
}

func getCodeLensFromCommand(issue snyk.Issue, command snyk.Command) sglsp.CodeLens {
	return sglsp.CodeLens{
		Range: workspace.ToRange(issue.Range),
		Command: sglsp.Command{
			Title:     command.Title,
			Command:   command.Command,
			Arguments: command.Arguments,
		},
	}
}

func CodeAction() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.CodeActionParams) ([]lsp.CodeAction, error) {
		log.Info().Str("method", "CodeActionHandler").Msg("RECEIVING")
		defer log.Info().Str("method", "CodeActionHandler").Msg("SENDING")

		filePath := uri.PathFromUri(params.TextDocument.URI)
		requestedRange := workspace.FromRange(params.Range)
		actions := workspace.Get().GetFolderContaining(filePath).CodeActions(filePath, requestedRange)
		return workspace.ToCodeActions(actions), nil
	})
}

func WorkspaceDidChangeWorkspaceFoldersHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeWorkspaceFoldersParams) (interface{}, error) {
		log.Info().Str("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Msg("RECEIVING")
		defer log.Info().Str("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Msg("SENDING")

		w := workspace.Get()
		for _, folder := range params.Event.Removed {
			w.DeleteFolder(uri.PathFromUri(folder.Uri))
		}
		for _, folder := range params.Event.Added {
			AddFolder(folder, w)
		}
		w.ScanWorkspace(ctx)
		return nil, nil
	})
}

func AddFolder(lspFolder lsp.WorkspaceFolder, w *workspace.Workspace) {
	f := workspace.NewFolder(uri.PathFromUri(lspFolder.Uri), lspFolder.Name, di.Scanner(), di.HoverService())
	w.AddFolder(f)
}

func InitializeHandler(srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializeParams) (interface{}, error) {
		method := "InitializeHandler"
		log.Info().Str("method", method).Interface("params", params).Msg("RECEIVING")
		UpdateSettings(ctx, params.InitializationOptions)
		w := workspace.New(di.Instrumentor())
		workspace.Set(w)

		// async processing listener
		go createProgressListener(progress.Channel, srv)
		go registerNotifier(srv)
		go func() {
			if params.ProcessID == 0 {
				// if started on its own, no need to exit or to monitor
				return
			}

			monitorClientProcess(params.ProcessID)
			log.Info().Msgf("Shutting down as client pid %d not running anymore.", params.ProcessID)
			os.Exit(0)
		}()

		if len(params.WorkspaceFolders) > 0 {
			for _, workspaceFolder := range params.WorkspaceFolders {
				log.Info().Str("method", method).Msgf("Adding workspaceFolder %v", workspaceFolder)
				AddFolder(workspaceFolder, w)
			}
		} else {
			AddFolder(lsp.WorkspaceFolder{Uri: uri.PathToUri(params.RootPath), Name: params.ClientInfo.Name}, w)
		}
		w.ScanWorkspace(ctx)

		return lsp.InitializeResult{
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
				WorkspaceFoldersServerCapabilities: &lsp.WorkspaceFoldersServerCapabilities{
					Supported:           true,
					ChangeNotifications: "snyk-ls",
				},
				HoverProvider:      true,
				CodeActionProvider: true,
				CodeLensProvider:   &sglsp.CodeLensOptions{ResolveProvider: false},
			},
		}, nil
	})
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

func Shutdown() jrpc2.Handler {
	return handler.New(func(ctx context.Context) (interface{}, error) {
		log.Info().Str("method", "Shutdown").Msg("RECEIVING")
		defer log.Info().Str("method", "Shutdown").Msg("SENDING")
		di.ErrorReporter().FlushErrorReporting()

		disposeProgressListener()
		notification.DisposeListener()
		return nil, nil
	})
}

func Exit(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context) (interface{}, error) {
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

func TextDocumentDidOpenHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidOpenTextDocumentParams) (interface{}, error) {
		method := "TextDocumentDidOpenHandler"
		filePath := uri.PathFromUri(params.TextDocument.URI)
		log.Info().Str("method", method).Str("documentURI", filePath).Msg("RECEIVING")
		folder := workspace.Get().GetFolderContaining(filePath)
		if folder != nil {
			folder.ScanFile(ctx, filePath)
		} else {
			log.Warn().Str("method", method).Str("documentURI", filePath).Msg("Not scanning, file not part of workspace")
		}
		return nil, nil
	})
}

func TextDocumentDidSaveHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidSaveTextDocumentParams) (interface{}, error) {
		method := "TextDocumentDidSaveHandler"
		log.Info().Str("method", method).Interface("params", params).Msg("RECEIVING")
		filePath := uri.PathFromUri(params.TextDocument.URI)

		// todo can we push cache management down?
		f := workspace.Get().GetFolderContaining(filePath)
		if f != nil {
			f.ClearDiagnosticsCache(filePath)
			di.HoverService().DeleteHover(params.TextDocument.URI)
			f.ScanFile(ctx, filePath)
		} else {
			log.Warn().Str("method", method).Str("documentURI", filePath).Msg("Not scanning, file not part of workspace")
		}
		return nil, nil
	})
}

func TextDocumentHover() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params hover.Params) (hover.Result, error) {
		log.Info().Str("method", "TextDocumentHover").Interface("params", params).Msg("RECEIVING")

		hoverResult := di.HoverService().GetHover(params.TextDocument.URI, params.Position)
		return hoverResult, nil
	})
}

func WindowWorkDoneProgressCancelHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.WorkdoneProgressCancelParams) (interface{}, error) {
		log.Info().Str("method", "WindowWorkDoneProgressCancelHandler").Interface("params", params).Msg("RECEIVING")
		CancelProgress(params.Token)
		return nil, nil
	})
}

func NoOpHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidCloseTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "NoOpHandler").Interface("params", params).Msg("RECEIVING")
		return nil, nil
	})
}

func registerNotifier(srv *jrpc2.Server) {
	callbackFunction := func(params interface{}) {
		switch params := params.(type) {
		case lsp.AuthenticationParams:
			notifier(srv, "$/snyk.hasAuthenticated", params)
			log.Info().Str("method", "notifyCallback").
				Msg("sending token")
		case lsp.SnykIsAvailableCli:
			notifier(srv, "$/snyk.isAvailableCli", params)
			log.Info().Str("method", "notifyCallback").
				Msg("sending cli path")
		case sglsp.ShowMessageParams:
			notifier(srv, "window/showMessage", params)
			log.Info().
				Str("method", "notifyCallback").
				Interface("message", params).
				Msg("showing message")
		case lsp.PublishDiagnosticsParams:
			notifier(srv, "textDocument/publishDiagnostics", params)
			source := "LSP"
			if len(params.Diagnostics) > 0 {
				source = params.Diagnostics[0].Source
			}
			log.Info().
				Str("method", "notifyCallback").
				Interface("documentURI", params.URI).
				Interface("source", source).
				Interface("diagnosticCount", len(params.Diagnostics)).
				Msg("publishing diagnostics")
		default:
			log.Warn().
				Str("method", "notifyCallback").
				Interface("params", params).
				Msg("received unconfigured notification object")
		}
	}
	notification.CreateListener(callbackFunction)
	log.Info().Str("method", "registerNotifier").Msg("registered notifier")
}

type RPCLogger struct{}

func (R RPCLogger) LogRequest(ctx context.Context, req *jrpc2.Request) {
	log.Debug().Msgf("Incoming JSON-RPC request. Method=%s. ID=%s. Is notification=%v.", req.Method(), req.ID(), req.IsNotification())
}

func (R RPCLogger) LogResponse(ctx context.Context, rsp *jrpc2.Response) {
	log.Err(rsp.Error()).Msg("Outgoing JSON-RPC response error")
	log.Debug().Msgf("Outgoing JSON-RPC response. ID=%s", rsp.ID())
}
