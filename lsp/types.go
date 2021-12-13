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

	/**
	* An optional property to describe the error code.
	*
	* @since 3.16.0
	 */
	CodeDescription CodeDescription `json:"codeDescription,omitempty"`

	/**
	* Additional metadata about the diagnostic.
	*
	* @since 3.15.0
	 */
	Tags []DiagnosticTag `json:"diagnosticTag,omitempty"`

	/**
	* An array of related diagnostic information, e.g. when symbol-names within
	* a scope collide all definitions can be marked via this property.
	 */
	RelatedInformation []DiagnosticRelatedInformation `json:"relatedInformation,omitempty"`

	/**
	* A data entry field that is preserved between a
	* `textDocument/publishDiagnostics` notification and
	* `textDocument/codeAction` request.
	*
	* @since 3.16.0
	 */
	Data interface{} `json:"data,omitempty"`
}

type DiagnosticTag int

//goland:noinspection GoCommentStart
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

type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities,omitempty"`
}

type ServerCapabilities struct {
	TextDocumentSync                   *lsp.TextDocumentSyncOptionsOrKind   `json:"textDocumentSync,omitempty"`
	HoverProvider                      bool                                 `json:"hoverProvider,omitempty"`
	CompletionProvider                 *lsp.CompletionOptions               `json:"completionProvider,omitempty"`
	SignatureHelpProvider              *lsp.SignatureHelpOptions            `json:"signatureHelpProvider,omitempty"`
	DefinitionProvider                 bool                                 `json:"definitionProvider,omitempty"`
	TypeDefinitionProvider             bool                                 `json:"typeDefinitionProvider,omitempty"`
	ReferencesProvider                 bool                                 `json:"referencesProvider,omitempty"`
	DocumentHighlightProvider          bool                                 `json:"documentHighlightProvider,omitempty"`
	DocumentSymbolProvider             bool                                 `json:"documentSymbolProvider,omitempty"`
	WorkspaceSymbolProvider            bool                                 `json:"workspaceSymbolProvider,omitempty"`
	ImplementationProvider             bool                                 `json:"implementationProvider,omitempty"`
	CodeActionProvider                 bool                                 `json:"codeActionProvider,omitempty"`
	CodeLensProvider                   *lsp.CodeLensOptions                 `json:"codeLensProvider,omitempty"`
	DocumentFormattingProvider         bool                                 `json:"documentFormattingProvider,omitempty"`
	DocumentRangeFormattingProvider    bool                                 `json:"documentRangeFormattingProvider,omitempty"`
	DocumentOnTypeFormattingProvider   *lsp.DocumentOnTypeFormattingOptions `json:"documentOnTypeFormattingProvider,omitempty"`
	RenameProvider                     bool                                 `json:"renameProvider,omitempty"`
	ExecuteCommandProvider             *lsp.ExecuteCommandOptions           `json:"executeCommandProvider,omitempty"`
	SemanticHighlighting               *lsp.SemanticHighlightingOptions     `json:"semanticHighlighting,omitempty"`
	WorkspaceFoldersServerCapabilities *WorkspaceFoldersServerCapabilities  `json:"workspaceFoldersServerCapabilities,omitempty"`
}

type WorkspaceFoldersServerCapabilities struct {
	/**
	 * The server has support for workspace folders
	 */
	Supported bool `json:"supported,omitempty"`

	/**
	 * Whether the server wants to receive workspace folder
	 * change notifications.
	 *
	 * If a string is provided, the string is treated as an ID
	 * under which the notification is registered on the client
	 * side. The ID can be used to unregister for these events
	 * using the `client/unregisterCapability` request.
	 */
	ChangeNotifications string `json:"changeNotifications,omitempty"`
}

type WorkspaceFolder struct {
	/**
	 * The associated URI for this workspace folder.
	 */
	Uri lsp.DocumentURI `json:"uri,omitempty"`

	/**
	 * The name of the workspace folder. Used to refer to this
	 * workspace folder in the user interface.
	 */
	Name string `json:"name,omitempty"`
}
