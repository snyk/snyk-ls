package server

import (
	"context"
	"os"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config/environment"
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
	logger       = environment.Logger
)

func Start() {
	var srv *jrpc2.Server
	diagnostics.SetSnykCodeService(&code.SnykCodeBackendService{})

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

	ctx := context.Background()
	logger.WithField("method", "Start").Info(ctx, "Starting up...")
	srv = srv.Start(channel.Header("")(os.Stdin, os.Stdout))

	_ = srv.Wait()
	logger.WithField("method", "Start").Info(ctx, "Exiting...")
}

func WorkspaceDidChangeWorkspaceFoldersHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeWorkspaceFoldersParams) (interface{}, error) {
		logger.WithField("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Info(ctx, "RECEIVING")
		defer logger.WithField("method", "WorkspaceDidChangeWorkspaceFoldersHandler").Info(ctx, "SENDING")

		for _, folder := range params.Event.Removed {
			diagnostics.ClearWorkspaceFolderDiagnostics(context.Background(), folder)
		}
		diagnostics.WorkspaceScan(context.Background(), params.Event.Added)

		return nil, nil
	})
}

func InitializeHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializeParams) (interface{}, error) {
		logger.WithField("method", "InitializeHandler").WithField("params", params).Info(ctx, "RECEIVING")
		defer logger.WithField("method", "InitializeHandler").Info(ctx, "SENDING")

		clientParams = params

		// async processing listener
		go hover.CreateHoverListener()
		go createProgressListener(progress.Channel, *srv)
		go registerNotifier(*srv)

		if len(clientParams.WorkspaceFolders) > 0 {
			go diagnostics.WorkspaceScan(context.Background(), clientParams.WorkspaceFolders)
		} else {
			go diagnostics.GetDiagnostics(context.Background(), clientParams.RootURI)
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
		logger.WithField("method", "Shutdown").Info(ctx, "RECEIVING")
		defer logger.WithField("method", "Shutdown").Info(ctx, "SENDING")

		error_reporting.FlushErrorReporting()

		disposeProgressListener()
		notification.DisposeListener()
		return nil, nil
	})
}

func Exit(srv **jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context) (interface{}, error) {
		logger.WithField("method", "Exit").Info(ctx, "RECEIVING")
		defer logger.WithField("method", "Exit").Info(ctx, "Stopping server...")

		(*srv).Stop()
		error_reporting.FlushErrorReporting()
		return nil, nil
	})
}

func TextDocumentDidChangeHandler() handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidChangeTextDocumentParams) (interface{}, error) {
		logger.WithField("method", "TextDocumentDidChangeHandler").Info(ctx, "RECEIVING")
		return nil, nil
	})
}

func PublishDiagnostics(ctx context.Context, uri sglsp.DocumentURI, srv **jrpc2.Server) {
	diags := diagnostics.GetDiagnostics(ctx, uri)
	if diags != nil {
		diagnosticsParams := lsp.PublishDiagnosticsParams{
			URI:         uri,
			Diagnostics: diags,
		}
		logger.WithField("method", "PublishDiagnostics").
			WithField("uri", diagnosticsParams.URI).
			Info(ctx, "SENDING")
		err := (*srv).Notify(ctx, "textDocument/publishDiagnostics", diagnosticsParams)
		logError(ctx, err, "PublishDiagnostics")
	}
}

func logError(ctx context.Context, err error, method string) {
	if err != nil {
		logger.WithField("method", method).WithError(err).Error(ctx, "error")
		error_reporting.CaptureError(err)
	}
}

func TextDocumentDidOpenHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidOpenTextDocumentParams) (interface{}, error) {
		logger.
			WithField("method", "TextDocumentDidOpenHandler").
			WithField("documentURI", string(params.TextDocument.URI)).
			Info(ctx, "RECEIVING")

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
		logger.
			WithField("method", "TextDocumentDidSaveHandler").
			WithField("params", params).
			Info(ctx, "RECEIVING")
		// clear cache when saving and get fresh diagnostics
		diagnostics.ClearDiagnosticsCache(params.TextDocument.URI)
		hover.DeleteHover(params.TextDocument.URI)
		PublishDiagnostics(ctx, params.TextDocument.URI, srv) // todo: remove in favor of notifier
		return nil, nil
	})
}

func TextDocumentWillSaveHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.WillSaveTextDocumentParams) (interface{}, error) {
		logger.
			WithField("method", "TextDocumentWillSaveHandler").
			WithField("params", params).
			Info(ctx, "RECEIVING")
		return nil, nil
	})
}

func TextDocumentWillSaveWaitUntilHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.WillSaveTextDocumentParams) (interface{}, error) {
		logger.
			WithField("method", "TextDocumentWillSaveWaitUntilHandler").
			WithField("params", params).
			Info(ctx, "RECEIVING")
		return nil, nil
	})
}

func TextDocumentDidCloseHandler() handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidCloseTextDocumentParams) (interface{}, error) {
		logger.
			WithField("method", "TextDocumentDidCloseHandler").
			WithField("params", params).
			Info(ctx, "RECEIVING")
		diagnostics.UnRegisterDocument(params.TextDocument.URI)
		return nil, nil
	})
}

func TextDocumentHover() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.HoverParams) (lsp.HoverResult, error) {
		logger.
			WithField("method", "TextDocumentHover").
			WithField("params", params).
			Info(ctx, "RECEIVING")

		hoverResult := hover.GetHover(params.TextDocument.URI, params.Position)
		return hoverResult, nil
	})
}

func WindowWorkDoneProgressCancelHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.WorkdoneProgressCancelParams) (interface{}, error) {
		logger.
			WithField("method", "WindowWorkDoneProgressCancelHandler").
			WithField("params", params).
			Info(ctx, "RECEIVING")
		CancelProgress(params.Token)
		return nil, nil
	})
}

func registerNotifier(srv *jrpc2.Server) {
	callbackFunction := func(params interface{}) {
		switch params := params.(type) {
		case lsp.AuthenticationParams:
			notifier(srv, "$/hasAuthenticated", params)
			logger.
				WithField("method", "notifyCallback").
				Info(context.Background(), "sending token")
		case sglsp.ShowMessageParams:
			notifier(srv, "window/showMessage", params)
			logger.
				WithField("method", "notifyCallback").
				WithField("params", params).
				Info(context.Background(), "showing message")
		case lsp.PublishDiagnosticsParams:
			notifier(srv, "textDocument/publishDiagnostics", params)
			logger.
				WithField("method", "notifyCallback").
				WithField("documentURI", params.URI).
				Info(context.Background(), "publishing diagnostics")
		default:
			logger.
				WithField("method", "notifyCallback").
				WithField("params", params).
				Warn(context.Background(), "received unconfigured notification type")
		}
	}
	notification.CreateListener(callbackFunction)
}
