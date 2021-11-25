package server

import (
	"context"
	"fmt"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"log"
	"strings"
	"testing"
)

var (
	srv *jrpc2.Server
	ctx = context.Background()
)

func startServer() server.Local {
	var srv *jrpc2.Server
	log.Printf("1: srv address: %p\n", &srv)

	lspHandlers := handler.Map{
		"initialize":             InitializeHandler(),
		"textDocument/didOpen":   TestDocumentDidOpenHandler(),
		"textDocument/didChange": TextDocumentDidChangeHandler(srv),
	}

	opts := &jrpc2.ServerOptions{
		AllowPush: true,
	}

	cpipe, spipe := channel.Direct()

	var loc = server.Local{
		Server: jrpc2.NewServer(lspHandlers, opts),
		Client: jrpc2.NewClient(cpipe, nil),
	}
	log.Printf("2: srv address: %p\n", &srv)

	srv = loc.Server
	loc.Server.Start(spipe)
	log.Printf("3: srv address: %p\n", &srv)
	return loc
}

func Test_serverShouldStart(t *testing.T) {
	// Construct a new server with methods "Hello" and "Log".
	loc := startServer()
	defer loc.Close()

	// We can query the server for its current status information, including a
	// list of its methods.
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
			URI:        "/test",
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
	rsp, err := loc.Client.Call(ctx, "textDocument/didChange", didChangeParams)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}

	// should receive diagnostics
	response := lsp.PublishDiagnosticsParams{}
	if err := rsp.UnmarshalResult(&response); err != nil {
		log.Fatalf("Decoding result: %v", err)
	}
	assert.Equal(t, didChangeParams.TextDocument.URI, response.URI)
}

//func ExampleResponse_UnmarshalResult() {
//	loc := startServer()
//	defer loc.Close()
//
//	rsp, err := loc.Client.Call(ctx, "Echo", []string{"alpha", "oscar", "kilo"})
//	if err != nil {
//		log.Fatalf("Call: %v", err)
//	}
//	var r1, r3 string
//
//	// Note the nil, which tells the decoder to skip that argument.
//	if err := rsp.UnmarshalResult(&handler.Args{&r1, nil, &r3}); err != nil {
//		log.Fatalf("Decoding result: %v", err)
//	}
//	fmt.Println(r1, r3)
//	// Output:
//	// alpha kilo
//}

//
//func ExampleClient_CallResult() {
//	loc := startServer()
//	defer loc.Close()
//
//	var msg string
//	if err := loc.Client.CallResult(ctx, "Hello", nil, &msg); err != nil {
//		log.Fatalf("CallResult: %v", err)
//	}
//	fmt.Println(msg)
//	// Output:
//	// Hello, world!
//}
