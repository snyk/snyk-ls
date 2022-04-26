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
	"github.com/snyk/snyk-ls/lsp"
)

var (
	clientParams lsp.InitializeParams
)

func Start() {
	var srv *jrpc2.Server
	diagnostics.SnykCode = &code.SnykCodeBackendService{}

	lspHandlers := handler.Map{
		"initialize":                          InitializeHandler(),
		"textDocument/didOpen":                TextDocumentDidOpenHandler(&srv),
		"textDocument/didChange":              TextDocumentDidChangeHandler(),
		"textDocument/didClose":               TextDocumentDidCloseHandler(),
		"textDocument/didSave":                TextDocumentDidSaveHandler(&srv),
		"textDocument/willSave":               TextDocumentWillSaveHandler(),
		"textDocument/willSaveWaitUntil":      TextDocumentWillSaveWaitUntilHandler(),
		"shutdown":                            Shutdown(),
		"exit":                                Exit(&srv),
		"workspace/didChangeWorkspaceFolders": WorkspaceDidChangeWorkspaceFoldersHandler(),
		"textDocument/hover":                  TextDocumentHover(),
	}

	srv = jrpc2.NewServer(lspHandlers, &jrpc2.ServerOptions{
		AllowPush: true,
	})

	log.Info().Msg("Starting up...")
	srv = srv.Start(channel.Header("")(os.Stdin, os.Stdout))

	err := srv.Wait()
	log.Err(err).Msg("Exiting...")
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
		diagnostics.UpdateDocument(params.TextDocument.URI, params.ContentChanges)
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
	}
}

func TextDocumentDidOpenHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidOpenTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentDidOpenHandler").Interface("params", params).Msg("RECEIVING")
		diagnostics.RegisterDocument(params.TextDocument)
		PublishDiagnostics(ctx, params.TextDocument.URI, srv)
		return nil, nil
	})
}

func TextDocumentDidSaveHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidSaveTextDocumentParams) (interface{}, error) {
		log.Info().Str("method", "TextDocumentDidSaveHandler").Interface("params", params).Msg("RECEIVING")
		// clear cache when saving and get fresh diagnostics
		diagnostics.ClearDiagnosticsCache(params.TextDocument.URI)
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

func TextDocumentHover() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.HoverParams) (lsp.HoverResult, error) {
		log.Info().Str("method", "TextDocumentHover").Interface("params", params).Msg("RECEIVING")
		diags := diagnostics.GetDiagnostics(params.TextDocument.URI)

		var hover string
		for _, d := range diags {
			if d.Range.Start.Line == params.Position.Line {
				log.Info().Msgf("Issue details: %v", d.Message)
				hover += d.Message + "\n\n\n"
			}
		}

		return lsp.HoverResult{
			Contents: lsp.MarkupContent{
				Kind:  "markdown",
				Value: hover,
			},
		}, nil
	})
}
func InitializeHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.InitializeParams) (interface{}, error) {
		log.Info().Str("method", "InitializeHandler").Interface("params", params).Msg("RECEIVING")
		clientParams = params

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
						Change:            sglsp.TDSKFull,
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
