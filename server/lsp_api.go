package server

import "github.com/sourcegraph/go-lsp"

const (
	SAVE_REASON_MANUAL      TextDocumentSaveReason = 0
	SAVE_REASON_AFTER_DELAY TextDocumentSaveReason = 1
	SAVE_REASON_FOCUS_OUT   TextDocumentSaveReason = 2
)

type TextDocumentSaveReason int

type WillSaveTextDocumentParams struct {
	TextDocument lsp.TextDocumentIdentifier `json:"textDocument"`
	Reason       TextDocumentSaveReason     `json:"reason"`
}
