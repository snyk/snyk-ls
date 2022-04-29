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
	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/diagnostics"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	clientParams lsp.InitializeParams
)

func Start() {
	var srv *jrpc2.Server
	diagnostics.SnykCode = &code.SnykCodeBackendService{}

	lspHandlers := handler.Map{
		"initialize":                          InitializeHandler(&srv), // todo: type messages
		"textDocument/didOpen":                TextDocumentDidOpenHandler(&srv),
		"textDocument/didChange":              TextDocumentDidChangeHandler(),
		"textDocument/didClose":               TextDocumentDidCloseHandler(),
		"textDocument/didSave":                TextDocumentDidSaveHandler(&srv),
		"textDocument/willSave":               TextDocumentWillSaveHandler(),
		"textDocument/willSaveWaitUntil":      TextDocumentWillSaveWaitUntilHandler(),
		"shutdown":                            Shutdown(),
		"exit":                                Exit(&srv),
		"textDocument/codeLens":               TextDocumentCodeLens(),
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

func Shutdown() jrpc2.Handler {
	return handler.New(func(ctx context.Context) (interface{}, error) {
		log.Info().Str("method", "Shutdown").Msg("RECEIVING")
		log.Info().Str("method", "Shutdown").Msg("SENDING")

		disposeProgressListener()
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

func TextDocumentCodeLens() handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.CodeLensParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentCodeLens").Interface("params", params).Msg("RECEIVING")

		codeLenses, err := diagnostics.GetCodeLenses(params.TextDocument.URI)
		if err != nil {
			log.Err(err).Str("method", "TextDocumentCodeLens")
		}

		log.Info().Str("method", "TextDocumentCodeLens").Interface("response", codeLenses).Msg("SENDING")
		return codeLenses, err
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
			environment.EnsureCLI() // first would trigger download
			diagnostics.RegisterDocument(params.TextDocument)
			PublishDiagnostics(ctx, params.TextDocument.URI, srv)
		}()

		return nil, nil
	})
}

func TextDocumentDidSaveHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidSaveTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentDidSaveHandler").Interface("params", params).Msg("RECEIVING")
		// clear cache when saving and get fresh diagnostics
		diagnostics.ClearDiagnosticsCache(params.TextDocument.URI)
		diagnostics.ClearLenses(params.TextDocument.URI)
		PublishDiagnostics(ctx, params.TextDocument.URI, srv)
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

func WindowWorkDoneProgressCancelHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.WorkdoneProgressCancelParams) (interface{}, error) {
		log.Info().Str("method", "WindowWorkDoneProgressCancelHandler").Interface("params", params).Msg("RECEIVING")
		CancelProgress(params.Token)
		return nil, nil
	})
}

func InitializeHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializeParams) (interface{}, error) {
		log.Info().Str("method", "InitializeHandler").Interface("params", params).Msg("RECEIVING")
		clientParams = params

		if len(clientParams.WorkspaceFolders) > 0 {
			go diagnostics.WorkspaceScan(clientParams.WorkspaceFolders)
		} else {
			go diagnostics.GetDiagnostics(clientParams.RootURI)
		}

		if clientParams.Capabilities.Window.WorkDoneProgress {
			go createProgressListener(progress.ProgressChannel, *srv)
		}

		return lsp.InitializeResult{
			Capabilities: lsp.ServerCapabilities{
				TextDocumentSync: &sglsp.TextDocumentSyncOptionsOrKind{
					Options: &sglsp.TextDocumentSyncOptions{
						OpenClose:         true,
						Change:            sglsp.TDSKFull,
						WillSave:          true,
						WillSaveWaitUntil: true,
						Save:              &sglsp.SaveOptions{IncludeText: true},
					},
				},
				CodeLensProvider: &sglsp.CodeLensOptions{ResolveProvider: true},
				WorkspaceFoldersServerCapabilities: &lsp.WorkspaceFoldersServerCapabilities{
					Supported:           true,
					ChangeNotifications: "snyk-ls",
				},
			},
		}, nil
	})
}
