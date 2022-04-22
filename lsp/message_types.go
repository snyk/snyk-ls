package lsp

import (
	sglsp "github.com/sourcegraph/go-lsp"
)

const (
	Manual     TextDocumentSaveReason = 0
	AfterDelay TextDocumentSaveReason = 1
	FocusOut   TextDocumentSaveReason = 2
)

type TextDocumentSaveReason int

type DiagnosticResult struct {
	Uri         sglsp.DocumentURI
	Diagnostics []Diagnostic
	Err         error
}

type CodeLensResult struct {
	Uri        sglsp.DocumentURI
	CodeLenses []sglsp.CodeLens
	Err        error
}

type WillSaveTextDocumentParams struct {
	TextDocument sglsp.TextDocumentIdentifier `json:"textDocument"`
	Reason       TextDocumentSaveReason       `json:"reason"`
}

type Uri string

type CodeDescription struct {
	Href Uri `json:"href"`
}

type PublishDiagnosticsParams struct {
	URI         sglsp.DocumentURI `json:"uri"`
	Diagnostics []Diagnostic      `json:"diagnostics"`
}

type Diagnostic struct {
	/**
	 * The range at which the message applies.
	 */
	Range sglsp.Range `json:"range"`

	/**
	 * The diagnostic's severity. Can be omitted. If omitted it is up to the
	 * client to interpret diagnostics as error, warning, info or hint.
	 */
	Severity sglsp.DiagnosticSeverity `json:"severity,omitempty"`

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
	Location sglsp.Location `json:"location"`
	Message  string         `json:"message"`
}

type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities,omitempty"`
}

type InitializeParams struct {
	ProcessID int `json:"processId,omitempty"`

	// RootPath is DEPRECATED in favor of the RootURI field.
	RootPath string `json:"rootPath,omitempty"`

	RootURI               sglsp.DocumentURI        `json:"rootUri,omitempty"`
	ClientInfo            sglsp.ClientInfo         `json:"clientInfo,omitempty"`
	Trace                 sglsp.Trace              `json:"trace,omitempty"`
	InitializationOptions interface{}              `json:"initializationOptions,omitempty"`
	Capabilities          sglsp.ClientCapabilities `json:"capabilities"`

	WorkDoneToken    string            `json:"workDoneToken,omitempty"`
	WorkspaceFolders []WorkspaceFolder `json:"workspaceFolders,omitempty"`
}

type ServerCapabilities struct {
	TextDocumentSync                   *sglsp.TextDocumentSyncOptionsOrKind   `json:"textDocumentSync,omitempty"`
	HoverProvider                      bool                                   `json:"hoverProvider,omitempty"`
	CompletionProvider                 *sglsp.CompletionOptions               `json:"completionProvider,omitempty"`
	SignatureHelpProvider              *sglsp.SignatureHelpOptions            `json:"signatureHelpProvider,omitempty"`
	DefinitionProvider                 bool                                   `json:"definitionProvider,omitempty"`
	TypeDefinitionProvider             bool                                   `json:"typeDefinitionProvider,omitempty"`
	ReferencesProvider                 bool                                   `json:"referencesProvider,omitempty"`
	DocumentHighlightProvider          bool                                   `json:"documentHighlightProvider,omitempty"`
	DocumentSymbolProvider             bool                                   `json:"documentSymbolProvider,omitempty"`
	WorkspaceSymbolProvider            bool                                   `json:"workspaceSymbolProvider,omitempty"`
	ImplementationProvider             bool                                   `json:"implementationProvider,omitempty"`
	CodeActionProvider                 bool                                   `json:"codeActionProvider,omitempty"`
	CodeLensProvider                   *sglsp.CodeLensOptions                 `json:"codeLensProvider,omitempty"`
	DocumentFormattingProvider         bool                                   `json:"documentFormattingProvider,omitempty"`
	DocumentRangeFormattingProvider    bool                                   `json:"documentRangeFormattingProvider,omitempty"`
	DocumentOnTypeFormattingProvider   *sglsp.DocumentOnTypeFormattingOptions `json:"documentOnTypeFormattingProvider,omitempty"`
	RenameProvider                     bool                                   `json:"renameProvider,omitempty"`
	ExecuteCommandProvider             *sglsp.ExecuteCommandOptions           `json:"executeCommandProvider,omitempty"`
	SemanticHighlighting               *sglsp.SemanticHighlightingOptions     `json:"semanticHighlighting,omitempty"`
	WorkspaceFoldersServerCapabilities *WorkspaceFoldersServerCapabilities    `json:"workspaceFoldersServerCapabilities,omitempty"`
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
	// The associated Uri for this workspace folder.
	Uri sglsp.DocumentURI `json:"uri,omitempty"`

	// The Name of the workspace folder. Used to refer to this
	// workspace folder in the user interface.
	Name string `json:"name,omitempty"`
}

type DidChangeWorkspaceFoldersParams struct {
	// The actual workspace folder change Event.
	Event WorkspaceFoldersChangeEvent `json:"Event,omitempty"`
}

// WorkspaceFoldersChangeEvent The workspace folder change event.
type WorkspaceFoldersChangeEvent struct {
	// The array of Added workspace folders
	Added []WorkspaceFolder `json:"Added,omitempty"`

	// The array of the Removed workspace folders
	Removed []WorkspaceFolder `json:"Removed,omitempty"`
}

type Settings struct {
	ActivateSnykOpenSource string `json:"activateSnykOpenSource,omitempty"`
	ActivateSnykCode       string `json:"activateSnykCode,omitempty"`
	ActivateSnykIac        string `json:"activateSnykIac,omitempty"`
	Insecure               string `json:"insecure,omitempty"`
	Endpoint               string `json:"endpoint,omitempty"`
	AdditionalParams       string `json:"additionalParams,omitempty"`
	AdditionalEnv          string `json:"additionalEnv,omitempty"`
	Path                   string `json:"path,omitempty"`
}

type DidChangeConfigurationParams struct {
	// The actual changed settings
	Settings Settings `json:"settings"`
}

type ProgressToken string

type ProgressParams struct {
	/**
	 * The progress token provided by the client or server.
	 */
	Token ProgressToken `json:"token"`
	/**
	 * The progress data.
	 */
	Value interface{} `json:"value,omitempty"`
}

type WorkDoneProgressKind struct {
	Kind string `json:"kind"`
}

type WorkDoneProgressBegin struct {
	WorkDoneProgressKind
	/**
	 * Mandatory title of the progress operation. Used to briefly inform about
	 * the kind of operation being performed.
	 *
	 * Examples: "Indexing" or "Linking dependencies".
	 */
	Title string `json:"title"`
	/**
	 * Controls if a cancel button should show to allow the user to cancel the
	 * long running operation. Clients that don't support cancellation are allowed
	 * to ignore the setting.
	 */
	Cancellable bool `json:"cancellable,omitempty"`
	/**
	 * Optional, more detailed associated progress message. Contains
	 * complementary information to the `title`.
	 *
	 * Examples: "3/25 files", "project/src/module2", "node_modules/some_dep".
	 * If unset, the previous progress message (if any) is still valid.
	 */
	Message string `json:"message,omitempty"`
	/**
	 * Optional progress percentage to display (value 100 is considered 100%).
	 * If not provided infinite progress is assumed and clients are allowed
	 * to ignore the `percentage` value in subsequent in report notifications.
	 *
	 * The value should be steadily rising. Clients are free to ignore values
	 * that are not following this rule. The value range is [0, 100].
	 */
	Percentage uint32 `json:"percentage,omitempty"`
}

type WorkDoneProgressReport struct {
	WorkDoneProgressKind
	/**
	 * Controls enablement state of a cancel button.
	 *
	 * Clients that don't support cancellation or don't support controlling the button's
	 * enablement state are allowed to ignore the property.
	 */
	Cancellable bool `json:"cancellable,omitempty"`
	/**
	 * Optional, more detailed associated progress message. Contains
	 * complementary information to the `title`.
	 *
	 * Examples: "3/25 files", "project/src/module2", "node_modules/some_dep".
	 * If unset, the previous progress message (if any) is still valid.
	 */
	Message string `json:"message,omitempty"`
	/**
	 * Optional progress percentage to display (value 100 is considered 100%).
	 * If not provided infinite progress is assumed and clients are allowed
	 * to ignore the `percentage` value in subsequent in report notifications.
	 *
	 * The value should be steadily rising. Clients are free to ignore values
	 * that are not following this rule. The value range is [0, 100]
	 */
	Percentage uint32 `json:"percentage,omitempty"`
}
type WorkDoneProgressEnd struct {
	WorkDoneProgressKind
	/**
	 * Optional, a final message indicating to for example indicate the outcome
	 * of the operation.
	 */
	Message string `json:"message,omitempty"`
}

type WorkdoneProgressCancelParams struct {
	Token ProgressToken `json:"token"`
}
