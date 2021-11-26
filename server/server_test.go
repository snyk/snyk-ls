package server

import (
	"context"
	"fmt"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"log"
	"strings"
	"testing"
)

var (
	ctx          = context.Background()
	notification *jrpc2.Request
)

func startServer() server.Local {
	var srv *jrpc2.Server

	lspHandlers := handler.Map{
		"initialize":             InitializeHandler(),
		"textDocument/didOpen":   TestDocumentDidOpenHandler(),
		"textDocument/didChange": TextDocumentDidChangeHandler(&srv),
	}

	opts := &server.LocalOptions{
		Client: &jrpc2.ClientOptions{
			OnNotify: func(request *jrpc2.Request) {
				notification = request
			},
		},
		Server: &jrpc2.ServerOptions{
			AllowPush: true,
		},
	}
	loc := server.NewLocal(lspHandlers, opts)
	srv = loc.Server
	return loc
}

func Test_serverShouldStart(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	si := loc.Server.ServerInfo()

	fmt.Println(strings.Join(si.Methods, "\n"))
}

func Test_dummy_shouldNotBeServed(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	_, err := loc.Client.Call(ctx, "dummy", nil)
	if err == nil {
		log.Fatalf("Call: %v", err)
	}
}

func Test_initialize_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatalf("Decoding result: %v", err)
	}
	fmt.Println(result)
}

func Test_initialize_shouldSupportDocumentOpening(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatalf("Decoding result: %v", err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.OpenClose, true)
}

func Test_initialize_shouldSupportDocumentChanges(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatalf("Decoding result: %v", err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.Change, lsp.TDSKFull)
}

func Test_textDocumentDidOpenHandler_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	rsp, err := loc.Client.Call(ctx, "textDocument/didOpen", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatalf("Decoding result: %v", err)
	}
	fmt.Println(result)
}

func Test_textDocumentDidOpenHandler_shouldAcceptDocumentItem(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	didOpenParams := getDidOpenTextParams()

	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
}

func getDidOpenTextParams() lsp.DidOpenTextDocumentParams {
	// see https://microsoft.github.io/language-server-protocol/specifications/specification-3-17/#documentSelector
	didOpenParams := lsp.DidOpenTextDocumentParams{
		TextDocument: lsp.TextDocumentItem{
			URI:        "/dummy.java",
			LanguageID: "java",
			Version:    0,
			Text:       "public void",
		},
	}
	return didOpenParams
}

func Test_textDocumentDidChangeHandler_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	rsp, err := loc.Client.Call(ctx, "textDocument/didChange", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatalf("Decoding result: %v", err)
	}
	fmt.Println(result)
}

func Test_textDocumentDidChangeHandler_should_publish_diagnostics(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	// register our dummy document
	didOpenParams := getDidOpenTextParams()
	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)

	// send change
	versionedTextDocumentIdentifier := lsp.VersionedTextDocumentIdentifier{
		TextDocumentIdentifier: lsp.TextDocumentIdentifier{URI: didOpenParams.TextDocument.URI},
		Version:                didOpenParams.TextDocument.Version,
	}

	didChangeParams := lsp.DidChangeTextDocumentParams{
		TextDocument:   versionedTextDocumentIdentifier,
		ContentChanges: nil,
	}

	_, err = loc.Client.Call(ctx, "textDocument/didChange", didChangeParams)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}

	// wait for all workers done

	// should receive diagnostics
	assert.NotNil(t, notification)
	diagnostics := lsp.PublishDiagnosticsParams{}
	notification.UnmarshalParams(&diagnostics)
	assert.Equal(t, didChangeParams.TextDocument.URI, diagnostics.URI)
}
