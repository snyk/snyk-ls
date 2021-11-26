package server

import (
	"context"
	"fmt"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/sirupsen/logrus"
	"github.com/snyk/snyk-lsp/code"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"log"
	"strings"
	"testing"
	"time"
)

var (
	ctx          = context.Background()
	notification *jrpc2.Request
)

func startServer() server.Local {
	var srv *jrpc2.Server

	lspHandlers := handler.Map{
		"initialize":                     InitializeHandler(),
		"textDocument/didOpen":           TextDocumentDidOpenHandler(&srv),
		"textDocument/didChange":         TextDocumentDidChangeHandler(),
		"textDocument/didClose":          TextDocumentDidCloseHandler(),
		"textDocument/didSave":           TextDocumentDidSaveHandler(&srv),
		"textDocument/willSave":          TextDocumentWillSaveHandler(),
		"textDocument/willSaveWaitUntil": TextDocumentWillSaveWaitUntilHandler(),
	}

	Logger = logrus.New()

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
	fmt.Println(rsp)
}

func Test_textDocumentDidOpenHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	didOpenParams := didOpenTextParams()

	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}

	// should receive diagnostics
	diagnostics := lsp.PublishDiagnosticsParams{}

	// wait for publish
	assert.Eventually(t, func() bool { return notification != nil }, 500*time.Millisecond, 1)
	_ = notification.UnmarshalParams(&diagnostics)
	assert.Equal(t, didOpenParams.TextDocument.URI, diagnostics.URI)
}

func didOpenTextParams() lsp.DidOpenTextDocumentParams {
	// see https://microsoft.github.io/language-server-protocol/specifications/specification-3-17/#documentSelector
	didOpenParams := lsp.DidOpenTextDocumentParams{
		TextDocument: lsp.TextDocumentItem{
			URI:        code.FakeDiagnosticUri,
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
	fmt.Println(rsp)
}

func Test_textDocumentDidChangeHandler_shouldAcceptUri(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	// register our dummy document
	didOpenParams := didOpenTextParams()
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
}

func Test_textDocumentDidSaveHandler_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	rsp, err := loc.Client.Call(ctx, "textDocument/didSave", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
	fmt.Println(rsp)
}

func Test_textDocumentWillSaveWaitUntilHandler_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	rsp, err := loc.Client.Call(ctx, "textDocument/willSaveWaitUntil", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
	fmt.Println(rsp)
}

func Test_textDocumentWillSaveHandler_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	rsp, err := loc.Client.Call(ctx, "textDocument/willSave", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
	fmt.Println(rsp)
}
