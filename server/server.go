package server

import (
	"context"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/sirupsen/logrus"
	"github.com/snyk/snyk-lsp/code"
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
		"textDocument/didOpen":           TextDocumentDidOpenHandler(&server),
		"textDocument/didChange":         TextDocumentDidChangeHandler(),
		"textDocument/didClose":          TextDocumentDidCloseHandler(),
		"textDocument/didSave":           TextDocumentDidSaveHandler(&server),
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

func TextDocumentDidChangeHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.DidChangeTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentDidChangeHandler", "params": params}).Info("RECEIVING")
		snyklsp.UpdateDocument(params.TextDocument.URI, params.ContentChanges)
		return nil, nil
	})
}

func PublishDiagnostics(ctx context.Context, uri lsp.DocumentURI, srv **jrpc2.Server) (interface{}, error) {
	diagnostics, err := snyklsp.GetDiagnostics(uri, &code.FakeBackendService{BundleHash: "dummy"})
	logError(err, "PublishDiagnostics")
	if diagnostics != nil {
		diagnosticsParams := lsp.PublishDiagnosticsParams{
			URI:         uri,
			Diagnostics: diagnostics,
		}
		Logger.WithFields(logrus.Fields{"method": "PublishDiagnostics", "params": diagnosticsParams}).Info("SENDING")
		err := (*srv).Notify(ctx, "textDocument/publishDiagnostics", diagnosticsParams)
		logError(err, "PublishDiagnostics")
	}
	return nil, nil
}

func logError(err error, method string) {
	if err != nil {
		Logger.WithField("method", method).Error(err)
	}
}

func TextDocumentDidOpenHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.DidOpenTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentDidOpenHandler", "params": params}).Info("RECEIVING")
		snyklsp.RegisterDocument(params.TextDocument)
		PublishDiagnostics(ctx, params.TextDocument.URI, srv)
		return nil, nil
	})
}

func TextDocumentDidSaveHandler(srv **jrpc2.Server) handler.Func {
	return handler.New(func(ctx context.Context, params lsp.DidSaveTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentDidSaveHandler", "params": params}).Info("RECEIVING")
		PublishDiagnostics(ctx, params.TextDocument.URI, srv)
		return nil, nil
	})
}

func TextDocumentWillSaveHandler() handler.Func {
	return handler.New(func(ctx context.Context, params WillSaveTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentWillSaveHandler", "params": params}).Info("RECEIVING")
		return nil, nil
	})
}

func TextDocumentWillSaveWaitUntilHandler() handler.Func {
	return handler.New(func(ctx context.Context, params WillSaveTextDocumentParams) (interface{}, error) {
		Logger.WithFields(logrus.Fields{"method": "TextDocumentWillSaveWaitUntilHandler", "params": params}).Info("RECEIVING")
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
						Save:              &lsp.SaveOptions{IncludeText: true},
					},
				},
			},
		}, nil
	})
}
