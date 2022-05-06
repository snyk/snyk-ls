package server

import (
	"context"
	"os"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/diagnostics"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/internal/hover"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	clientParams lsp.InitializeParams
)

func Start() {
	var srv *jrpc2.Server
	diagnostics.SetSnykCodeService(&code.FakeSnykCodeApiService{})

	lspHandlers := handler.Map{
		"initialize":                          InitializeHandler(&srv),
		"textDocument/didOpen":                TextDocumentDidOpenHandler(&srv),
		"textDocument/didChange":              TextDocumentDidChangeHandler(),
		"textDocument/didClose":               TextDocumentDidCloseHandler(),
		"textDocument/didSave":                TextDocumentDidSaveHandler(&srv),
		"textDocument/hover":                  TextDocumentHover(),
		"textDocument/willSave":               TextDocumentWillSaveHandler(),
		"textDocument/willSaveWaitUntil":      TextDocumentWillSaveWaitUntilHandler(),
		"shutdown":                            Shutdown(),
		"exit":                                Exit(&srv),
		"workspace/didChangeWorkspaceFolders": WorkspaceDidChangeWorkspaceFoldersHandler(),
		"workspace/didChangeConfiguration":    WorkspaceDidChangeConfiguration(),
		"window/workDoneProgress/cancel":      WindowWorkDoneProgressCancelHandler(),
		// "codeLens/resolve":               codeLensResolve(&server),
	}

	srv = jrpc2.NewServer(lspHandlers, &jrpc2.ServerOptions{
		AllowPush: true,
	})

	log.Info().Msg("Starting up...")
	srv = srv.Start(channel.Header("")(os.Stdin, os.Stdout))

	_ = srv.Wait()
	log.Info().Msg("Exiting...")
}

func WorkspaceDidChangeWorkspaceFoldersHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeWorkspaceFoldersParams) (interface{}, error) {
		log.Info().Str("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Msg("RECEIVING")
		log.Info().Str("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Msg("SENDING")

		for _, folder := range params.Event.Removed {
			diagnostics.ClearWorkspaceFolderDiagnostics(folder)
		}
		diagnostics.WorkspaceScan(params.Event.Added)

		return nil, nil
	})
}

func InitializeHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializeParams) (interface{}, error) {
		log.Info().Str("method", "InitializeHandler").Interface("params", params).Msg("RECEIVING")
		clientParams = params

		// async processing listener
		go hover.CreateHoverListener()
		go createProgressListener(progress.ProgressChannel, *srv)
		go registerNotifier(*srv)

		if len(clientParams.WorkspaceFolders) > 0 {
			go diagnostics.WorkspaceScan(clientParams.WorkspaceFolders)
		} else {
			go diagnostics.GetDiagnostics(clientParams.RootURI)
		}

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
		error_reporting.FlushErrorReporting()

		disposeProgressListener()
		notification.DisposeListener()
		return nil, nil
	})
}

func Exit(srv **jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context) (interface{}, error) {
		log.Info().Str("method", "Exit").Msg("RECEIVING")
		log.Info().Msg("Stopping server...")
		(*srv).Stop()
		error_reporting.FlushErrorReporting()
		return nil, nil
	})
}

func TextDocumentDidChangeHandler() handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidChangeTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentDidChangeHandler").Interface("params", params).Msg("RECEIVING")
		return nil, nil
	})
}

func PublishDiagnostics(ctx context.Context, uri sglsp.DocumentURI, srv **jrpc2.Server) {
	diags := diagnostics.GetDiagnostics(uri)
	if diags != nil {
		diagnosticsParams := lsp.PublishDiagnosticsParams{
			URI:         uri,
			Diagnostics: diags,
		}
		log.Info().Str("method", "PublishDiagnostics").Str("uri", string(diagnosticsParams.URI)).Msg("SENDING")
		err := (*srv).Notify(ctx, "textDocument/publishDiagnostics", diagnosticsParams)
		logError(err, "PublishDiagnostics")
	}
}

func logError(err error, method string) {
	if err != nil {
		log.Err(err).Str("method", method)
		error_reporting.CaptureError(err)
	}
}

func TextDocumentDidOpenHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidOpenTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentDidOpenHandler").Str("documentURI", string(params.TextDocument.URI)).Msg("RECEIVING")

		go func() {
			preconditions.EnsureReadyForAnalysisAndWait()
			diagnostics.RegisterDocument(params.TextDocument)
			PublishDiagnostics(ctx, params.TextDocument.URI, srv) // todo: remove in favor of notifier
		}()

		return nil, nil
	})
}

func TextDocumentDidSaveHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidSaveTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentDidSaveHandler").Interface("params", params).Msg("RECEIVING")
		// clear cache when saving and get fresh diagnostics
		diagnostics.ClearDiagnosticsCache(params.TextDocument.URI)
		hover.DeleteHover(params.TextDocument.URI)
		PublishDiagnostics(ctx, params.TextDocument.URI, srv) // todo: remove in favor of notifier
		return nil, nil
	})
}

func TextDocumentWillSaveHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.WillSaveTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentWillSaveHandler").Interface("params", params).Msg("RECEIVING")
		return nil, nil
	})
}

func TextDocumentWillSaveWaitUntilHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.WillSaveTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentWillSaveWaitUntilHandler").Interface("params", params).Msg("RECEIVING")
		return nil, nil
	})
}

func TextDocumentDidCloseHandler() handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidCloseTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentDidCloseHandler").Interface("params", params).Msg("RECEIVING")
		diagnostics.UnRegisterDocument(params.TextDocument.URI)
		return nil, nil
	})
}

func TextDocumentHover() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.HoverParams) (lsp.HoverResult, error) {
		log.Info().Str("method", "TextDocumentHover").Interface("params", params).Msg("RECEIVING")

		hoverResult := hover.GetHover(params.TextDocument.URI, params.Position)
		return hoverResult, nil
	})
}

func WindowWorkDoneProgressCancelHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.WorkdoneProgressCancelParams) (interface{}, error) {
		log.Info().Str("method", "WindowWorkDoneProgressCancelHandler").Interface("params", params).Msg("RECEIVING")
		CancelProgress(params.Token)
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
}
