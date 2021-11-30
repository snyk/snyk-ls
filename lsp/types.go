package lsp

import (
	"github.com/sourcegraph/go-lsp"
)

const (
	Manual     TextDocumentSaveReason = 0
	AfterDelay TextDocumentSaveReason = 1
	FocusOut   TextDocumentSaveReason = 2
)

type TextDocumentSaveReason int

type WillSaveTextDocumentParams struct {
	TextDocument lsp.TextDocumentIdentifier `json:"textDocument"`
	Reason       TextDocumentSaveReason     `json:"reason"`
}

type Uri string

type CodeDescription struct {
	Href Uri `json:"href"`
}

type PublishDiagnosticsParams struct {
	URI         lsp.DocumentURI `json:"uri"`
	Diagnostics []Diagnostic    `json:"diagnostics"`
}

type Diagnostic struct {
	/**
	 * The range at which the message applies.
	 */
	Range lsp.Range `json:"range"`

	/**
	 * The diagnostic's severity. Can be omitted. If omitted it is up to the
	 * client to interpret diagnostics as error, warning, info or hint.
	 */
	Severity lsp.DiagnosticSeverity `json:"severity,omitempty"`

	/**
	 * The diagnostic's code. Can be omitted.
	 */
	Code string `json:"code,omitempty"`

	/**
	 * A human-readable string describing the source of this
	 * diagnostic, e.g. 'typescript' or 'super lint'.
	 */
	Source string `json:"source,omitempty"`

	/**
	 * The diagnostic's message.
	 */
	Message string `json:"message"`

	///**
	//* An optional property to describe the error code.
	//*
	//* @since 3.16.0
	//*/
	//CodeDescription CodeDescription `json:"codeDescription,omitempty"`
	//
	///**
	//* Additional metadata about the diagnostic.
	//*
	//* @since 3.15.0
	//*/
	//Tags []DiagnosticTag `json:"diagnosticTag,omitempty"`
	//
	///**
	//* An array of related diagnostic information, e.g. when symbol-names within
	//* a scope collide all definitions can be marked via this property.
	//*/
	//RelatedInformation []DiagnosticRelatedInformation `json:"relatedInformation,omitempty"`
	//
	///**
	//* A data entry field that is preserved between a
	//* `textDocument/publishDiagnostics` notification and
	//* `textDocument/codeAction` request.
	//*
	//* @since 3.16.0
	//*/
	//Data interface{} `json:"data,omitempty"`
}

type DiagnosticTag int

const (
	/**
	 * Unused or unnecessary code.
	 *
	 * Clients are allowed to render diagnostics with this tag faded out
	 * instead of having an error squiggle.
	 */
	Unnecessary DiagnosticTag = 1

	/**
	 * Deprecated or obsolete code.
	 *
	 * Clients are allowed to rendered diagnostics with this tag strike through.
	 */
	Deprecated DiagnosticTag = 2
)

type DiagnosticRelatedInformation struct {
	Location lsp.Location `json:"location"`
	Message  string       `json:"message"`
}
