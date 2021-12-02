package server

import (
	"context"
	"fmt"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/sirupsen/logrus"
	"github.com/snyk/snyk-lsp/code"
	"github.com/snyk/snyk-lsp/util"
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
	doc          = lsp.TextDocumentItem{
		URI:        code.FakeDiagnosticUri,
		LanguageID: "java",
		Version:    0,
		Text:       "public class AnnotatorTest {\n  public static void delay(long millis) {\n    try {\n      Thread.sleep(millis);\n    } catch (InterruptedException e) {\n      e.printStackTrace();\n    }\n  }\n}",
	}
	docIdentifier = lsp.VersionedTextDocumentIdentifier{
		TextDocumentIdentifier: lsp.TextDocumentIdentifier{URI: doc.URI},
		Version:                doc.Version,
	}
)

func didOpenTextParams() lsp.DidOpenTextDocumentParams {
	// see https://microsoft.github.io/language-server-protocol/specifications/specification-3-17/#documentSelector
	didOpenParams := lsp.DidOpenTextDocumentParams{
		TextDocument: doc,
	}
	return didOpenParams
}

func didSaveTextParams() lsp.DidSaveTextDocumentParams {
	// see https://microsoft.github.io/language-server-protocol/specifications/specification-3-17/#documentSelector
	didSaveParams := lsp.DidSaveTextDocumentParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: doc.URI},
	}
	return didSaveParams
}

func startServer() server.Local {
	var err error
	util.CliPath, err = util.SetupCLI()
	if err != nil {
		log.Fatal(err)
	}
	util.Logger = logrus.New()

	var srv *jrpc2.Server

	var service code.FakeBackendService

	lspHandlers := handler.Map{
		"initialize":                     InitializeHandler(),
		"textDocument/didOpen":           TextDocumentDidOpenHandler(&srv, &service),
		"textDocument/didChange":         TextDocumentDidChangeHandler(),
		"textDocument/didClose":          TextDocumentDidCloseHandler(),
		"textDocument/didSave":           TextDocumentDidSaveHandler(&srv, &service),
		"textDocument/willSave":          TextDocumentWillSaveHandler(),
		"textDocument/willSaveWaitUntil": TextDocumentWillSaveWaitUntilHandler(),
		"textDocument/codeLens":          TextDocumentCodeLens(),
		//"codeLens/resolve":               codeLensResolve(&server),
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

func Test_initialize_shouldSupportDocumentSaving(t *testing.T) {
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
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.Save, &lsp.SaveOptions{IncludeText: true})
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSave, true)
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSaveWaitUntil, true)
}

func Test_initialize_shouldSupportCodeLens(t *testing.T) {
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
	assert.Equal(t, result.Capabilities.CodeLensProvider.ResolveProvider, true)
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
	assert.Eventually(t, func() bool { return notification != nil }, 5*time.Second, 10*time.Millisecond)
	notification.UnmarshalParams(&diagnostics)
	assert.Equal(t, didOpenParams.TextDocument.URI, diagnostics.URI)
}

func Test_textDocumentDidChangeHandler_shouldAcceptUri(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	// register our dummy document
	didOpenParams := didOpenTextParams()
	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)

	didChangeParams := lsp.DidChangeTextDocumentParams{
		TextDocument:   docIdentifier,
		ContentChanges: nil,
	}

	_, err = loc.Client.Call(ctx, "textDocument/didChange", didChangeParams)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
}

func Test_textDocumentDidSaveHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	didSaveParams := didSaveTextParams()

	_, err := loc.Client.Call(ctx, "textDocument/didSave", didSaveParams)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}

	// should receive diagnostics
	diagnostics := lsp.PublishDiagnosticsParams{}

	// wait for publish
	assert.Eventually(t, func() bool { return notification != nil }, 5*time.Second, 10*time.Millisecond)
	notification.UnmarshalParams(&diagnostics)
	assert.Equal(t, didSaveParams.TextDocument.URI, diagnostics.URI)
}

func Test_textDocumentWillSaveWaitUntilHandler_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	_, err := loc.Client.Call(ctx, "textDocument/willSaveWaitUntil", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
}

func Test_textDocumentWillSaveHandler_shouldBeServed(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	_, err := loc.Client.Call(ctx, "textDocument/willSave", nil)
	if err != nil {
		log.Fatalf("Call: %v", err)
	}
}

func Test_textDocumentCodeLens_shouldReturnCodeLenses(t *testing.T) {
	loc := startServer()
	defer loc.Close()

	codeLensParams := lsp.CodeLensParams{
		TextDocument: docIdentifier.TextDocumentIdentifier,
	}

	// populate caches
	rsp, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenTextParams())
	if err != nil {
		util.Logger.Fatal(err)
	}
	rsp, err = loc.Client.Call(ctx, "textDocument/codeLens", codeLensParams)
	if err != nil {
		util.Logger.Fatal(err)
	}

	var codeLenses []lsp.CodeLens
	rsp.UnmarshalResult(&codeLenses)
	assert.Equal(t, 1, len(codeLenses))
}

//func Test_codeLensResolve_shouldResolve(t *testing.T) {
//	assert.Fail(t, "Not implemented yet")
//}
