package server

import (
	"context"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/sirupsen/logrus"
	"github.com/snyk/snyk-lsp/code/bundle"
	snyklsp "github.com/snyk/snyk-lsp/code/lsp"
	"github.com/sourcegraph/go-lsp"
	"log"
	"os"
)

var Logger *logrus.Logger

func Start() {
	logFile, err := os.OpenFile("/tmp/snyk-lsp.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()

	Logger = logrus.New()
	Logger.SetOutput(logFile)

	var server *jrpc2.Server

	lspHandlers := handler.Map{
		"initialize":                     InitializeHandler(),
		"textDocument/didOpen":           TextDocumentDidOpenHandler(),
		"textDocument/didChange":         TextDocumentDidChangeHandler(&server),
		"textDocument/didClose":          TextDocumentDidCloseHandler(),
		"textDocument/didSave":           TextDocumentDidSaveHandler(),
		"textDocument/willSave":          TextDocumentWillSaveHandler(),
		"textDocument/willSaveWaitUntil": TextDocumentWillSaveWaitUntilHandler(),
	}

	server = jrpc2.NewServer(lspHandlers, &jrpc2.ServerOptions{
		AllowPush: true,
	})

	Logger.Info("Starting up...")
	server = server.Start(channel.Header("")(os.Stdin, os.Stdout))

	err = server.Wait()
	log.Fatalf("Shutting down...(%s)", err)
}

func TextDocumentDidChangeHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.DidChangeTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentDidChangeHandler", "params": params}).Info("RECEIVING")

		err := PublishDiagnostics(ctx, params, srv)
		return nil, err
	})
}

func PublishDiagnostics(ctx context.Context, params lsp.DidChangeTextDocumentParams, srv **jrpc2.Server) error {
	diagnostics := snyklsp.GetDiagnostics(params.TextDocument.URI, &bundle.FakeBackendService{BundleHash: "dummy"})
	if diagnostics != nil {
		diagnosticsParams := lsp.PublishDiagnosticsParams{
			URI:         params.TextDocument.URI,
			Diagnostics: diagnostics,
		}
		Logger.WithFields(logrus.Fields{"method": "TextDocumentDidChangeHandler", "params": diagnosticsParams}).Info("SENDING")
		err := (*srv).Notify(ctx, "textDocument/publishDiagnostics", diagnosticsParams)
		return err
	}
	return nil
}

func TextDocumentDidOpenHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.DidOpenTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentDidOpenHandler", "params": params}).Info("RECEIVING")
		snyklsp.RegisterDocument(params.TextDocument)
		return nil, nil
	})
}

// todo testing
func TextDocumentDidSaveHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.DidSaveTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentDidSaveHandler", "params": params}).Info("RECEIVING")
		snyklsp.UnRegisterDocument(params.TextDocument.URI)
		return nil, nil
	})
}

// todo testing
func TextDocumentWillSaveHandler() handler.Func {
	return handler.New(func(ctx context.Context, params WillSaveTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentWillSaveHandler", "params": params}).Info("RECEIVING")
		snyklsp.UnRegisterDocument(params.TextDocument.URI)
		return nil, nil
	})
}

// todo testing
func TextDocumentWillSaveWaitUntilHandler() handler.Func {
	return handler.New(func(ctx context.Context, params WillSaveTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentWillSaveWaitUntilHandler", "params": params}).Info("RECEIVING")
		snyklsp.UnRegisterDocument(params.TextDocument.URI)
		return nil, nil
	})
}

//todo testing
func TextDocumentDidCloseHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.DidCloseTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentDidCloseHandler", "params": params}).Info("RECEIVING")
		snyklsp.UnRegisterDocument(params.TextDocument.URI)
		return nil, nil
	})
}

func InitializeHandler() handler.Func {
	return handler.New(func(ctx context.Context, _ *jrpc2.Request) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "InitializeHandler"}).Info("RECEIVING")
		return lsp.InitializeResult{
			Capabilities: lsp.ServerCapabilities{
				TextDocumentSync: &lsp.TextDocumentSyncOptionsOrKind{
					Options: &lsp.TextDocumentSyncOptions{
						OpenClose:         true,
						Change:            lsp.TDSKFull,
						WillSave:          true,
						WillSaveWaitUntil: true,
						Save:              &lsp.SaveOptions{IncludeText: false},
					},
				},
			},
		}, nil
	})
}
