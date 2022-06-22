package server

import (
	"context"
	"os"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

func Start() {
	var srv *jrpc2.Server
	di.Init()

	handlers := handler.Map{}
	srv = jrpc2.NewServer(handlers, &jrpc2.ServerOptions{
		AllowPush: true,
	})
	initHandlers(srv, &handlers)

	log.Info().Msg("Starting up...")
	srv = srv.Start(channel.Header("")(os.Stdin, os.Stdout))

	_ = srv.Wait()
	log.Info().Msg("Exiting...")
}

func initHandlers(srv *jrpc2.Server, handlers *handler.Map) {
	(*handlers)["initialize"] = InitializeHandler(srv)
	(*handlers)["textDocument/didOpen"] = TextDocumentDidOpenHandler(srv)
	(*handlers)["textDocument/didChange"] = NoOpHandler()
	(*handlers)["textDocument/didClose"] = NoOpHandler()
	(*handlers)["textDocument/didSave"] = TextDocumentDidSaveHandler(srv)
	(*handlers)["textDocument/hover"] = TextDocumentHover()
	(*handlers)["textDocument/willSave"] = NoOpHandler()
	(*handlers)["textDocument/willSaveWaitUntil"] = NoOpHandler()
	(*handlers)["shutdown"] = Shutdown()
	(*handlers)["exit"] = Exit(srv)
	(*handlers)["workspace/didChangeWorkspaceFolders"] = WorkspaceDidChangeWorkspaceFoldersHandler()
	(*handlers)["workspace/didChangeConfiguration"] = WorkspaceDidChangeConfiguration()
	(*handlers)["window/workDoneProgress/cancel"] = WindowWorkDoneProgressCancelHandler()
}

func WorkspaceDidChangeWorkspaceFoldersHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeWorkspaceFoldersParams) (interface{}, error) {
		log.Info().Str("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Msg("RECEIVING")
		log.Info().Str("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Msg("SENDING")

		w := workspace.Get()
		for _, folder := range params.Event.Removed {
			w.DeleteFolder(uri.PathFromUri(folder.Uri))
		}
		for _, folder := range params.Event.Added {
			AddFolder(folder, w)
		}
		w.Scan(ctx)
		return nil, nil
	})
}

func AddFolder(folder lsp.WorkspaceFolder, w *workspace.Workspace) {
	f := workspace.NewFolder(uri.PathFromUri(folder.Uri), folder.Name, w)
	w.AddFolder(f)
}

func InitializeHandler(srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializeParams) (interface{}, error) {
		method := "InitializeHandler"
		log.Info().Str("method", method).Interface("params", params).Msg("RECEIVING")
		w := workspace.New()
		workspace.Set(w)

		// async processing listener
		go createProgressListener(progress.Channel, srv)
		go registerNotifier(srv)

		if len(params.WorkspaceFolders) > 0 {
			for _, workspaceFolder := range params.WorkspaceFolders {
				AddFolder(workspaceFolder, w)
			}
		} else {
			AddFolder(lsp.WorkspaceFolder{Uri: uri.PathToUri(params.RootPath), Name: params.ClientInfo.Name}, w)
		}
		w.Scan(ctx)

		return lsp.InitializeResult{
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
				HoverProvider: true,
			},
		}, nil
	})
}

func Shutdown() jrpc2.Handler {
	return handler.New(func(ctx context.Context) (interface{}, error) {
		log.Info().Str("method", "Shutdown").Msg("RECEIVING")
		log.Info().Str("method", "Shutdown").Msg("SENDING")
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

func PublishDiagnostics(ctx context.Context, documentURI sglsp.DocumentURI, srv *jrpc2.Server) {
	method := "PublishDiagnostics"
	diags := workspace.Get().GetDiagnostics(ctx, uri.PathFromUri(documentURI))
	if diags != nil {
		diagnosticsParams := lsp.PublishDiagnosticsParams{
			URI:         documentURI,
			Diagnostics: diags,
		}
		log.Info().Str("method", method).Str("uri", string(diagnosticsParams.URI)).Msg("SENDING")
		err := (*srv).Notify(ctx, "textDocument/publishDiagnostics", diagnosticsParams)
		logError(err, method)
	}
}

func logError(err error, method string) {
	if err != nil {
		log.Err(err).Str("method", method)
		di.ErrorReporter().CaptureError(err)
	}
}

func TextDocumentDidOpenHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidOpenTextDocumentParams) (interface{}, error) {
		method := "TextDocumentDidOpenHandler"
		log.Info().Str("method", method).Str("documentURI", string(params.TextDocument.URI)).Msg("RECEIVING")
		go func() {
			preconditions.EnsureReadyForAnalysisAndWait(ctx)
			PublishDiagnostics(ctx, params.TextDocument.URI, srv) // todo: remove in favor of notifier
		}()
		return nil, nil
	})
}

func TextDocumentDidSaveHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.DidSaveTextDocumentParams) (interface{}, error) {
		method := "TextDocumentDidSaveHandler"
		log.Info().Str("method", method).Interface("params", params).Msg("RECEIVING")

		// clear cache when saving and get fresh diagnostics
		filePath := uri.PathFromUri(params.TextDocument.URI)
		folder := workspace.Get().GetFolder(filePath)
		folder.ClearDiagnosticsCache(filePath)
		di.HoverService().DeleteHover(params.TextDocument.URI)
		PublishDiagnostics(ctx, params.TextDocument.URI, srv) // todo: remove in favor of notifier
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
			notifier(srv, "$/hasAuthenticated", params)
			log.Info().Str("method", "notifyCallback").
				Msg("sending token")
		case sglsp.ShowMessageParams:
			notifier(srv, "window/showMessage", params)
			log.Info().
				Str("method", "notifyCallback").
				Interface("message", params).
				Msg("showing message")
		case lsp.PublishDiagnosticsParams:
			notifier(srv, "textDocument/publishDiagnostics", params)
			log.Info().
				Str("method", "notifyCallback").
				Interface("documentURI", params.URI).
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
