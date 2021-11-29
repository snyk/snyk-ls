package server

import (
	"context"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/sirupsen/logrus"
	"github.com/snyk/snyk-lsp/code"
	"github.com/snyk/snyk-lsp/diagnostics"
	"github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/util"
	sglsp "github.com/sourcegraph/go-lsp"
	"log"
	"os"
)

func Start() {
	var err error
	util.CliPath, err = util.SetupCLI()
	if err != nil {
		logrus.Fatal(err)
	}

	var server *jrpc2.Server

	lspHandlers := handler.Map{
		"initialize":                     InitializeHandler(),
		"textDocument/didOpen":           TextDocumentDidOpenHandler(&server, &code.FakeBackendService{BundleHash: "hash"}),
		"textDocument/didChange":         TextDocumentDidChangeHandler(),
		"textDocument/didClose":          TextDocumentDidCloseHandler(),
		"textDocument/didSave":           TextDocumentDidSaveHandler(&server, &code.FakeBackendService{BundleHash: "hash"}),
		"textDocument/willSave":          TextDocumentWillSaveHandler(),
		"textDocument/willSaveWaitUntil": TextDocumentWillSaveWaitUntilHandler(),
		"textDocument/codeLens":          TextDocumentCodeLens(),
		//"codeLens/resolve":               codeLensResolve(&server),
	}

	server = jrpc2.NewServer(lspHandlers, &jrpc2.ServerOptions{
		AllowPush: true,
	})

	util.Logger.Info("Starting up...")
	server = server.Start(channel.Header("")(os.Stdin, os.Stdout))

	err = server.Wait()
	log.Fatalf("Shutting down...(%s)", err)
}

func TextDocumentCodeLens() handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.CodeLensParams) (interface{}, error) {
		util.Logger.WithFields(logrus.Fields{"method": "TextDocumentCodeLens", "params": params}).Info("RECEIVING")

		codeLenses, err := diagnostics.GetCodeLenses(params.TextDocument.URI)
		if err != nil {
			util.Logger.WithFields(logrus.Fields{"method": "TextDocumentCodeLens", "response": codeLenses}).Error(err)
		}

		util.Logger.WithFields(logrus.Fields{"method": "TextDocumentCodeLens", "response": codeLenses}).Info("SENDING")
		return codeLenses, err
	})
}

func TextDocumentDidChangeHandler() handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidChangeTextDocumentParams) (interface{}, error) {
		util.Logger.WithFields(logrus.Fields{"method": "TextDocumentDidChangeHandler", "params": params}).Info("RECEIVING")
		diagnostics.UpdateDocument(params.TextDocument.URI, params.ContentChanges)
		return nil, nil
	})
}

func PublishDiagnostics(ctx context.Context, uri sglsp.DocumentURI, srv **jrpc2.Server, backendService code.BackendService) (interface{}, error) {
	diags, err := diagnostics.GetDiagnostics(uri, backendService)
	logError(err, "PublishDiagnostics")
	if diags != nil {
		diagnosticsParams := lsp.PublishDiagnosticsParams{
			URI:         uri,
			Diagnostics: diags,
		}
		util.Logger.WithFields(logrus.Fields{"method": "PublishDiagnostics", "params": diagnosticsParams}).Info("SENDING")
		err := (*srv).Notify(ctx, "textDocument/publishDiagnostics", diagnosticsParams)
		logError(err, "PublishDiagnostics")
	}
	return nil, nil
}

func logError(err error, method string) {
	if err != nil {
		util.Logger.WithField("method", method).Error(err)
	}
}

func TextDocumentDidOpenHandler(srv **jrpc2.Server, backendService code.BackendService) handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidOpenTextDocumentParams) (interface{}, error) {
		util.Logger.WithFields(logrus.Fields{"method": "TextDocumentDidOpenHandler", "params": params}).Info("RECEIVING")
		diagnostics.RegisterDocument(params.TextDocument)
		PublishDiagnostics(ctx, params.TextDocument.URI, srv, backendService)
		return nil, nil
	})
}

func TextDocumentDidSaveHandler(srv **jrpc2.Server, backendService code.BackendService) handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidSaveTextDocumentParams) (interface{}, error) {
		util.Logger.WithFields(logrus.Fields{"method": "TextDocumentDidSaveHandler", "params": params}).Info("RECEIVING")
		// clear cache when saving and get fresh diagnostics
		diagnostics.ClearDiagnosticsCache(params.TextDocument.URI)
		diagnostics.ClearLenses(params.TextDocument.URI)
		// todo use real backend
		PublishDiagnostics(ctx, params.TextDocument.URI, srv, backendService)
		return nil, nil
	})
}

func TextDocumentWillSaveHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.WillSaveTextDocumentParams) (interface{}, error) {
		util.Logger.WithFields(logrus.Fields{"method": "TextDocumentWillSaveHandler", "params": params}).Info("RECEIVING")
		return nil, nil
	})
}

func TextDocumentWillSaveWaitUntilHandler() handler.Func {
	return handler.New(func(ctx context.Context, params lsp.WillSaveTextDocumentParams) (interface{}, error) {
		util.Logger.WithFields(logrus.Fields{"method": "TextDocumentWillSaveWaitUntilHandler", "params": params}).Info("RECEIVING")
		return nil, nil
	})
}

func TextDocumentDidCloseHandler() handler.Func {
	return handler.New(func(ctx context.Context, params sglsp.DidCloseTextDocumentParams) (interface{}, error) {
		util.Logger.WithFields(logrus.Fields{"method": "TextDocumentDidCloseHandler", "params": params}).Info("RECEIVING")
		diagnostics.UnRegisterDocument(params.TextDocument.URI)
		return nil, nil
	})
}

func InitializeHandler() handler.Func {
	return handler.New(func(ctx context.Context, _ *jrpc2.Request) (interface{}, error) {
		util.Logger.WithFields(logrus.Fields{"method": "InitializeHandler"}).Info("RECEIVING")
		return sglsp.InitializeResult{
			Capabilities: sglsp.ServerCapabilities{
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
			},
		}, nil
	})
}
