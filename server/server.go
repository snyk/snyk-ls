package server

import (
	"context"
	snykcode "github.com/snyk/snyk-lsp/snyk-code"
	"log"
	"os"
)
import (
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/sourcegraph/go-lsp"
)

func Start() {
	var server *jrpc2.Server

	lspHandlers := handler.Map{
		"initialize":             InitializeHandler(),
		"textDocument/didOpen":   TestDocumentDidOpenHandler(),
		"textDocument/didChange": TextDocumentDidChangeHandler(server),
	}

	server = jrpc2.NewServer(lspHandlers, &jrpc2.ServerOptions{
		AllowPush: true,
	})

	log.Println("Starting up...")
	server = server.Start(channel.Header("")(os.Stdin, os.Stdout))

	err := server.Wait()
	log.Fatalf("Shutting down...(%s)", err)
}

func TextDocumentDidChangeHandler(srv *jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.DidChangeTextDocumentParams) (interface{}, error) {
		diagnostics := snykcode.GetDiagnostics(params.TextDocument.URI, params.ContentChanges)
		err := srv.Notify(ctx, "textDocument/PublishDiagnostics", lsp.PublishDiagnosticsParams{
			URI:         params.TextDocument.URI,
			Diagnostics: diagnostics,
		})
		return nil, err
	})
}

func TestDocumentDidOpenHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.DidOpenTextDocumentParams) (interface{}, error) {
		snykcode.RegisterDocument(params.TextDocument)
		return nil, nil
	})
}

func InitializeHandler() handler.Func {
	return handler.New(func(ctx context.Context, _ *jrpc2.Request) (interface{}, error) {
		return lsp.InitializeResult{
			Capabilities: lsp.ServerCapabilities{
				TextDocumentSync: &lsp.TextDocumentSyncOptionsOrKind{
					Options: &lsp.TextDocumentSyncOptions{
						OpenClose: true,
						Change:    lsp.TDSKFull,
					},
				},
			},
		}, nil
	})
}
