/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package lsp

import (
	"github.com/google/uuid"
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

type DiagnosticSeverity int

const (
	DiagnosticsSeverityError       DiagnosticSeverity = 1
	DiagnosticsSeverityWarning     DiagnosticSeverity = 2
	DiagnosticsSeverityInformation DiagnosticSeverity = 3
	DiagnosticsSeverityHint        DiagnosticSeverity = 4
)

type Diagnostic struct {
	/**
	 * The range at which the message applies.
	 */
	Range sglsp.Range `json:"range"`

	/**
	 * The diagnostic's severity. Can be omitted. If omitted it is up to the
	 * client to interpret diagnostics as error, warning, info or hint.
	 */
	Severity DiagnosticSeverity `json:"severity,omitempty"`

	/**
	 * The diagnostic's code. Can be omitted. Can be string or int, thus we need
	 * any type
	 */
	Code any `json:"code,omitempty"`

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
	Data any `json:"data,omitempty"`
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
	ServerInfo   ServerInfo         `json:"serverInfo,omitempty"`
	Capabilities ServerCapabilities `json:"capabilities,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type InitializeParams struct {
	ProcessID int `json:"processId,omitempty"`

	// RootPath is DEPRECATED in favor of the RootURI field.
	RootPath string `json:"rootPath,omitempty"`

	// The rootUri of the workspace. Is null if no folder is open. If both `rootPath` and `rootUri` are set `rootUri` wins.
	RootURI               sglsp.DocumentURI  `json:"rootUri,omitempty"`
	ClientInfo            sglsp.ClientInfo   `json:"clientInfo,omitempty"`
	Trace                 sglsp.Trace        `json:"trace,omitempty"`
	InitializationOptions Settings           `json:"initializationOptions,omitempty"`
	Capabilities          ClientCapabilities `json:"capabilities"`

	WorkDoneToken    string            `json:"workDoneToken,omitempty"`
	WorkspaceFolders []WorkspaceFolder `json:"workspaceFolders,omitempty"`
}

type InitializedParams struct{}

type ServerCapabilities struct {
	TextDocumentSync                 *sglsp.TextDocumentSyncOptionsOrKind   `json:"textDocumentSync,omitempty"`
	HoverProvider                    bool                                   `json:"hoverProvider,omitempty"`
	CompletionProvider               *sglsp.CompletionOptions               `json:"completionProvider,omitempty"`
	SignatureHelpProvider            *sglsp.SignatureHelpOptions            `json:"signatureHelpProvider,omitempty"`
	DefinitionProvider               bool                                   `json:"definitionProvider,omitempty"`
	TypeDefinitionProvider           bool                                   `json:"typeDefinitionProvider,omitempty"`
	ReferencesProvider               bool                                   `json:"referencesProvider,omitempty"`
	DocumentHighlightProvider        bool                                   `json:"documentHighlightProvider,omitempty"`
	DocumentSymbolProvider           bool                                   `json:"documentSymbolProvider,omitempty"`
	WorkspaceSymbolProvider          bool                                   `json:"workspaceSymbolProvider,omitempty"`
	ImplementationProvider           bool                                   `json:"implementationProvider,omitempty"`
	CodeActionProvider               *CodeActionOptions                     `json:"codeActionProvider,omitempty"`
	CodeLensProvider                 *sglsp.CodeLensOptions                 `json:"codeLensProvider,omitempty"`
	DocumentFormattingProvider       bool                                   `json:"documentFormattingProvider,omitempty"`
	DocumentRangeFormattingProvider  bool                                   `json:"documentRangeFormattingProvider,omitempty"`
	DocumentOnTypeFormattingProvider *sglsp.DocumentOnTypeFormattingOptions `json:"documentOnTypeFormattingProvider,omitempty"`
	RenameProvider                   bool                                   `json:"renameProvider,omitempty"`
	ExecuteCommandProvider           *sglsp.ExecuteCommandOptions           `json:"executeCommandProvider,omitempty"`
	SemanticHighlighting             *sglsp.SemanticHighlightingOptions     `json:"semanticHighlighting,omitempty"`
	Workspace                        *Workspace                             `json:"workspace,omitempty"`
	InlineValueProvider              bool                                   `json:"inlineValueProvider,omitempty"`
}

type ClientCapabilities struct {
	Workspace    WorkspaceClientCapabilities    `json:"workspace,omitempty"`
	TextDocument TextDocumentClientCapabilities `json:"textDocument,omitempty"`
	Window       WindowClientCapabilities       `json:"window,omitempty"`
	Experimental interface{}                    `json:"experimental,omitempty"`
}

type CodeLensWorkspaceClientCapabilities struct {
	/**
	 * Whether the client implementation supports a refresh request sent from the
	 * server to the client.
	 *
	 * Note that this event is global and will force the client to refresh all
	 * code lenses currently shown. It should be used with absolute care and is
	 * useful for situation where a server for example detect a project wide
	 * change that requires such a calculation.
	 */
	RefreshSupport bool `json:"refreshSupport,omitempty"`
}

type InlineValueWorkspaceClientCapabilities struct {
	/**
	 * Whether the client implementation supports a refresh request sent from the
	 * server to the client.
	 *
	 * Note that this event is global and will force the client to refresh all
	 * inline values currently shown. It should be used with absolute care and is
	 * useful for situation where a server for example detect a project wide
	 * change that requires such a calculation.
	 */
	RefreshSupport bool `json:"refreshSupport,omitempty"`
}

type WorkspaceClientCapabilities struct {
	WorkspaceEdit struct {
		DocumentChanges    bool     `json:"documentChanges,omitempty"`
		ResourceOperations []string `json:"resourceOperations,omitempty"`
	} `json:"workspaceEdit,omitempty"`

	ApplyEdit bool `json:"applyEdit,omitempty"`

	Symbol struct {
		SymbolKind struct {
			ValueSet []int `json:"valueSet,omitempty"`
		} `json:"symbolKind,omitempty"`
	} `json:"symbol,omitempty"`

	DidChangeWatchedFiles *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	} `json:"didChangeWatchedFiles,omitempty"`

	ExecuteCommand *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	} `json:"executeCommand,omitempty"`

	WorkspaceFolders bool `json:"workspaceFolders,omitempty"`

	Configuration bool `json:"configuration,omitempty"`

	CodeLens CodeLensWorkspaceClientCapabilities `json:"codeLens,omitempty"`

	InlineValue InlineValueWorkspaceClientCapabilities `json:"inlineValue,omitempty"`
}

type TextDocumentClientCapabilities struct {
	Declaration *struct {
		LinkSupport bool `json:"linkSupport,omitempty"`
	} `json:"declaration,omitempty"`

	Definition *struct {
		LinkSupport bool `json:"linkSupport,omitempty"`
	} `json:"definition,omitempty"`

	Implementation *struct {
		LinkSupport bool `json:"linkSupport,omitempty"`

		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	} `json:"implementation,omitempty"`

	TypeDefinition *struct {
		LinkSupport bool `json:"linkSupport,omitempty"`
	} `json:"typeDefinition,omitempty"`

	Synchronization *struct {
		WillSave          bool `json:"willSave,omitempty"`
		DidSave           bool `json:"didSave,omitempty"`
		WillSaveWaitUntil bool `json:"willSaveWaitUntil,omitempty"`
	} `json:"synchronization,omitempty"`

	DocumentSymbol struct {
		SymbolKind struct {
			ValueSet []int `json:"valueSet,omitempty"`
		} `json:"symbolKind,omitempty"`

		HierarchicalDocumentSymbolSupport bool `json:"hierarchicalDocumentSymbolSupport,omitempty"`
	} `json:"documentSymbol,omitempty"`

	Formatting *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	} `json:"formatting,omitempty"`

	RangeFormatting *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	} `json:"rangeFormatting,omitempty"`

	Rename *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`

		PrepareSupport bool `json:"prepareSupport,omitempty"`
	} `json:"rename,omitempty"`

	SemanticHighlightingCapabilities *struct {
		SemanticHighlighting bool `json:"semanticHighlighting,omitempty"`
	} `json:"semanticHighlightingCapabilities,omitempty"`

	CodeAction struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`

		IsPreferredSupport bool `json:"isPreferredSupport,omitempty"`

		CodeActionLiteralSupport struct {
			CodeActionKind struct {
				ValueSet []CodeActionKind `json:"valueSet,omitempty"`
			} `json:"codeActionKind,omitempty"`
		} `json:"codeActionLiteralSupport,omitempty"`
	} `json:"codeAction,omitempty"`

	Completion struct {
		CompletionItem struct {
			DocumentationFormat []DocumentationFormat `json:"documentationFormat,omitempty"`
			SnippetSupport      bool                  `json:"snippetSupport,omitempty"`
		} `json:"completionItem,omitempty"`

		CompletionItemKind struct {
			ValueSet []CompletionItemKind `json:"valueSet,omitempty"`
		} `json:"completionItemKind,omitempty"`

		ContextSupport bool `json:"contextSupport,omitempty"`
	} `json:"completion,omitempty"`

	SignatureHelp *struct {
		SignatureInformation struct {
			ParameterInformation struct {
				LabelOffsetSupport bool `json:"labelOffsetSupport,omitempty"`
			} `json:"parameterInformation,omitempty"`
		} `json:"signatureInformation,omitempty"`
	} `json:"signatureHelp,omitempty"`

	DocumentLink *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`

		TooltipSupport bool `json:"tooltipSupport,omitempty"`
	} `json:"documentLink,omitempty"`

	Hover *struct {
		ContentFormat []string `json:"contentFormat,omitempty"`
	} `json:"hover,omitempty"`

	FoldingRange *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`

		RangeLimit interface{} `json:"rangeLimit,omitempty"`

		LineFoldingOnly bool `json:"lineFoldingOnly,omitempty"`
	} `json:"foldingRange,omitempty"`

	CallHierarchy *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	} `json:"callHierarchy,omitempty"`

	ColorProvider *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	} `json:"colorProvider,omitempty"`

	/**
	 * Capabilities specific to the `textDocument/inlineValue` request.
	 *
	 * @since 3.17.0
	 */
	InlineValue *struct {
		DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	} `json:"inlineValue,omitempty"`
}

/**
 * A parameter literal used in inline value requests.
 *
 * @since 3.17.0
 */
type InlineValueParams struct {
	/**
	 * The text document.
	 */
	TextDocument sglsp.TextDocumentIdentifier `json:"textDocument"`

	/**
	 * The document range for which inline values should be computed.
	 */
	Range sglsp.Range `json:"range"`

	/**
	 * Additional information about the context in which inline values were
	 * requested.
	 */
	Context InlineValueContext `json:"context"`
}

type InlineValueContext struct {
	/**
	 * The stack frame (as a DAP Id) where the execution has stopped.
	 */
	FrameId int `json:"frameId"`

	/**
	 * The document range where execution has stopped.
	 * Typically the end position of the range denotes the line where the
	 * inline values are shown.
	 */
	StoppedLocation sglsp.Range `json:"stoppedLocation"`
}

/**
 * Provide inline value as text.
 *
 * @since 3.17.0
 */
type InlineValue struct {
	/**
	 * The document range for which the inline value applies.
	 */
	Range sglsp.Range `json:"range"`

	/**
	 * The text of the inline value.
	 */
	Text string `json:"text"`
}

type DocumentationFormat string

type CompletionItemKind int

type WindowClientCapabilities struct {
	WorkDoneProgress bool `json:"workDoneProgress,omitempty"`
}

type Workspace struct {
	WorkspaceFolders *WorkspaceFoldersServerCapabilities `json:"workspaceFolders,omitempty"`
	FileOperations   *FileOperationsServerCapabilities   `json:"fileOperations,omitempty"`
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

type FileOperationsServerCapabilities struct {
	WillDeleteBool bool                             `json:"willDeleteBool,omitempty"`
	WillDelete     FileOperationRegistrationOptions `json:"willDelete,omitempty"`
}

type FileOperationPattern struct {
	Glob string `json:"glob,omitempty"`
}

type FileOperationFilter struct {
	Pattern FileOperationPattern `json:"pattern,omitempty"`
}

type FileOperationRegistrationOptions struct {
	Filters []FileOperationFilter `json:"filters,omitempty"`
}

type DeleteFilesParams struct {
	Files []FileDelete `json:"files,omitempty"`
}

type FileDelete struct {
	Uri sglsp.DocumentURI `json:"uri,omitempty"`
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

// Settings is the struct that is parsed from the InitializationParams.InitializationOptions field
type Settings struct {
	ActivateSnykOpenSource      string               `json:"activateSnykOpenSource,omitempty"`
	ActivateSnykCode            string               `json:"activateSnykCode,omitempty"`
	ActivateSnykIac             string               `json:"activateSnykIac,omitempty"`
	Insecure                    string               `json:"insecure,omitempty"`
	Endpoint                    string               `json:"endpoint,omitempty"`
	AdditionalParams            string               `json:"additionalParams,omitempty"`
	AdditionalEnv               string               `json:"additionalEnv,omitempty"`
	Path                        string               `json:"path,omitempty"`
	SendErrorReports            string               `json:"sendErrorReports,omitempty"`
	Organization                string               `json:"organization,omitempty"`
	EnableTelemetry             string               `json:"enableTelemetry,omitempty"`
	ManageBinariesAutomatically string               `json:"manageBinariesAutomatically,omitempty"`
	CliPath                     string               `json:"cliPath,omitempty"`
	Token                       string               `json:"token,omitempty"`
	IntegrationName             string               `json:"integrationName,omitempty"`
	IntegrationVersion          string               `json:"integrationVersion,omitempty"`
	AutomaticAuthentication     string               `json:"automaticAuthentication,omitempty"`
	DeviceId                    string               `json:"deviceId,omitempty"`
	FilterSeverity              SeverityFilter       `json:"filterSeverity,omitempty"`
	EnableTrustedFoldersFeature string               `json:"enableTrustedFoldersFeature,omitempty"`
	TrustedFolders              []string             `json:"trustedFolders,omitempty"`
	ActivateSnykCodeSecurity    string               `json:"activateSnykCodeSecurity,omitempty"`
	ActivateSnykCodeQuality     string               `json:"activateSnykCodeQuality,omitempty"`
	OsPlatform                  string               `json:"osPlatform,omitempty"`
	OsArch                      string               `json:"osArch,omitempty"`
	RuntimeVersion              string               `json:"runtimeVersion,omitempty"`
	RuntimeName                 string               `json:"runtimeName,omitempty"`
	ScanningMode                string               `json:"scanningMode,omitempty"`
	AuthenticationMethod        AuthenticationMethod `json:"authenticationMethod,omitempty"`
	SnykCodeApi                 string               `json:"snykCodeApi,omitempty"`
	EnableSnykLearnCodeActions  string               `json:"enableSnykLearnCodeActions,omitempty"`
}

type AuthenticationMethod string

const TokenAuthentication AuthenticationMethod = "token"
const OAuthAuthentication AuthenticationMethod = "oauth"

type DidChangeConfigurationParams struct {
	// The actual changed settings
	Settings Settings `json:"settings"`
}

type ConfigurationItem struct {
	/**
	 * The scope to get the configuration section for.
	 */
	ScopeURI string `json:"scopeUri,omitempty"`
	/**
	 * The configuration section asked for.
	 */
	Section string `json:"section,omitempty"`
}

/**
 * The parameters of a configuration request.
 */
type ConfigurationParams struct {
	Items []ConfigurationItem `json:"items"`
}

type AuthenticationParams struct {
	Token string `json:"token"`
}

type SnykIsAvailableCli struct {
	CliPath string `json:"cliPath"`
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
	Value any `json:"value,omitempty"`
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
	Percentage int `json:"percentage,omitempty"`
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
	Percentage int `json:"percentage,omitempty"`
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

type CodeActionContext struct {
	/**
	 * An array of diagnostics known on the client side overlapping the range provided to the
	 * `textDocument/codeAction` request. They are provided so that the server knows which
	 * errors are currently presented to the user for the given range. There is no guarantee
	 * that these accurately reflect the error state of the resource. The primary parameter
	 * to compute code actions is the provided range.
	 */
	Diagnostics []Diagnostic `json:"diagnostics"`
	/**
	 * Requested kind of actions to return.
	 *
	 * Actions not of this kind are filtered out by the client before being shown. So servers
	 * can omit computing them.
	 */
	Only []CodeActionKind `json:"only,omitempty"`
	/**
	 * The reason why code actions were requested.
	 *
	 * @since 3.17.0
	 */
	TriggerKind CodeActionTriggerKind `json:"triggerKind,omitempty"`
}

type CodeActionKind string

/**
 * Empty kind.
 */
const Empty CodeActionKind = ""

/**
 * Base kind for quickfix actions 'quickfix'.
 */
const QuickFix CodeActionKind = "quickfix"

/**
 * Base kind for refactoring actions 'refactor'.
 */
const Refactor CodeActionKind = "refactor"

/**
 * Base kind for refactoring extraction actions: 'refactor.extract'.
 *
 * Example extract actions:
 *
 * - Extract method
 * - Extract function
 * - Extract variable
 * - Extract interface from class
 * - ...
 */
const RefactorExtract CodeActionKind = "refactor.extract"

/**
 * Base kind for refactoring inline actions: 'refactor.inline'.
 *
 * Example inline actions:
 *
 * - Inline function
 * - Inline variable
 * - Inline constant
 * - ...
 */
const RefactorInline CodeActionKind = "refactor.inline"

/**
 * Base kind for refactoring rewrite actions: 'refactor.rewrite'.
 *
 * Example rewrite actions:
 *
 * - Convert JavaScript function to class
 * - Add or remove parameter
 * - Encapsulate field
 * - Make method static
 * - Move method to base class
 * - ...
 */
const RefactorRewrite CodeActionKind = "refactor.rewrite"

/**
 * Base kind for source actions: `source`.
 *
 * Source code actions apply to the entire file.
 */
const Source CodeActionKind = "source"

/**
 * Base kind for an organize imports source action
 * `source.organizeImports`.
 */
const SourceOrganizeImports CodeActionKind = "source.organizeImports"

/**
 * Base kind for a "fix all" source action `source.fixAll`.
 *
 * ""Fix all"" actions automatically fix errors that have a clear fix that
 * do not require user input. They should not suppress errors or perform
 * unsafe fixes such as generating new types or classes.
 *
 * @since 3.17.0
 */
const SourceFixAll CodeActionKind = "source.fixAll"

type CodeActionParams struct {
	/**
	 * The document in which the command was invoked.
	 */
	TextDocument sglsp.TextDocumentIdentifier `json:"textDocument"`
	/**
	 * The range for which the command was invoked.
	 */
	Range sglsp.Range `json:"range"`
	/**
	 * Context carrying additional information.
	 */
	Context CodeActionContext `json:"context"`
}

/**
 * A CodeAction represents a change that can be performed in code, e.g. to fix a problem or
 * to refactor code.
 *
 * A CodeAction can be of these forms:
 * 1. Has Edit but No Command - A simple edit that will be applied when the action is invoked
 * 2. Has Command but No Edit - A command that will be executed when the action is invoked
 * 3. Has both Edit and Command - A command that will be executed after the edit will be applied
 * 4. Has neither Edit nor Command - A deferred code action that would be resolved after codeAction/resolve is received.
 *
 * A deferred code action would have both Edit & Command omitted, and when invoked by the user, the server would send
 * a new CodeAction with the Edit and/or Command fields populated.
 */
type CodeAction struct {
	/**
	 * A short, human-readable, title for this code action.
	 */
	Title string `json:"title"`
	/**
	 * The kind of the code action.
	 *
	 * Used to filter code actions.
	 */
	Kind CodeActionKind `json:"kind,omitempty"`
	/**
	 * The diagnostics that this code action resolves.
	 */
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
	/**
	 * Marks this as a preferred action. Preferred actions are used by the `auto fix` command and can be targeted
	 * by keybindings.
	 *
	 * A quick fix should be marked preferred if it properly addresses the underlying error.
	 * A refactoring should be marked preferred if it is the most reasonable choice of actions to take.
	 *
	 * @since 3.15.0
	 */
	IsPreferred *bool `json:"isPreferred,omitempty"`
	/**
	 * Marks that the code action cannot currently be applied.
	 *
	 * Clients should follow the following guidelines regarding disabled code actions:
	 *
	 *   - Disabled code actions are not shown in automatic [lightbulb](https://code.visualstudio.com/docs/editor/editingevolved#_code-action)
	 *     code action menu.
	 *
	 *   - Disabled actions are shown as faded out in the code action menu when the user request a more specific type
	 *     of code action, such as refactorings.
	 *
	 *   - If the user has a [keybinding](https://code.visualstudio.com/docs/editor/refactoring#_keybindings-for-code-actions)
	 *     that auto applies a code action and only a disabled code actions are returned, the client should show the user an
	 *     error message with `reason` in the editor.
	 *
	 * @since 3.16.0
	 */
	Disabled *struct {
		/**
		 * Human readable description of why the code action is currently disabled.
		 *
		 * This is displayed in the code actions UI.
		 */
		Reason string `json:"reason"`
	} `json:"disabled,omitempty"`
	/**
	 * The workspace edit this code action performs.
	 */
	Edit *sglsp.WorkspaceEdit `json:"edit,omitempty"`

	/**
	 * A command this code action executes. If a code action
	 * provides an edit and a command, first the edit is
	 * executed and then the command.
	 */
	Command *sglsp.Command `json:"command,omitempty"`

	/**
	 * A data entry field that is preserved on a code action between
	 * a `textDocument/codeAction` and a `codeAction/resolve` request.
	 *
	 * Holds a UUID that is used to identify the code action in the resolve request.
	 */
	Data *CodeActionData `json:"data,omitempty"`
}

type CodeActionData uuid.UUID

type CodeActionTriggerKind float64

/**
 * Params to show a document.
 *
 * @since 3.16.0
 */
type ShowDocumentParams struct {
	/**
	 * The document uri to show.
	 */
	Uri sglsp.DocumentURI `json:"uri"`

	/**
	 * Indicates to show the resource in an external program.
	 * To show for example `https://code.visualstudio.com/`
	 * in the default WEB browser set `external` to `true`.
	 */
	External bool `json:"external"`

	/**
	 * An optional property to indicate whether the editor
	 * showing the document should take focus or not.
	 * Clients might ignore this property if an external
	 * program is started.
	 */
	TakeFocus bool `json:"takeFocus"`

	/**
	 * An optional selection range if the document is a text
	 * document. Clients might ignore the property if an
	 * external program is started or the file is not a text
	 * file.
	 */
	Selection sglsp.Range `json:"selection"`
}

type MessageActionItem struct {
	Title string `json:"title"`
}

type ShowMessageRequestParams struct {
	Type    MessageType         `json:"type"`
	Message string              `json:"message"`
	Actions []MessageActionItem `json:"actions"`
}

type ApplyWorkspaceEditParams struct {
	/**
	 * An optional label of the workspace edit. This label is
	 * presented in the user interface for example on an undo
	 * stack to undo the workspace edit.
	 */

	Label string `json:"label,omitempty"`
	/**
	 * The edits to apply.
	 */
	Edit *sglsp.WorkspaceEdit `json:"edit"`
}

type CodeLensRefresh struct{}
type InlineValueRefresh struct{}

type ApplyWorkspaceEditResult struct {
	/**
	 * Indicates whether the edit was applied or not.
	 */
	Applied bool `json:"applied"`

	/**
	* An optional textual description for why the edit was not applied.
	* This may be used by the server for diagnostic logging or to provide
	* a suitable error for a request that triggered the edit.
	 */
	FailureReason string `json:"failureReason,omitempty"`

	/**
	* Depending on the client's failure handling strategy `failedChange`
	* might contain the index of the change that failed. This property is
	* only available if the client signals a `failureHandling` strategy
	* in its client capabilities.
	 */
	FailedChange uint `json:"failedChange,omitempty"`
}

type MessageType int

const Error MessageType = 1
const Warning MessageType = 2
const Info MessageType = 3
const Log MessageType = 4

type LogMessageParams struct {
	/**
	 * The message type. See {@link MessageType}
	 */
	Type MessageType `json:"type"`

	/**
	 * The actual message
	 */
	Message string `json:"message"`
}

type LogTraceParams struct {
	/**
	 * The message to be logged.
	 */
	Message string `json:"message"`

	/**
	 * Additional information that can be computed if the `trace` configuration
	 * is set to `'verbose'`
	 */
	Verbose string `json:"verbose"`
}

type SnykTrustedFoldersParams struct {
	TrustedFolders []string `json:"trustedFolders"`
}

type ScanStatus string

const (
	InProgress  ScanStatus = "inProgress"
	Success     ScanStatus = "success"
	ErrorStatus ScanStatus = "error"
)

// SnykScanParams is the type for the $/snyk/scan message
type SnykScanParams struct {
	// Status can be either Initial, InProgress or Success
	Status ScanStatus `json:"status"`
	// Product under scan (Snyk Code, Snyk Open Source, etc...)
	Product string `json:"product"`
	// FolderPath is the root-folder of the current scan
	FolderPath string `json:"folderPath"`
	// Issues contain the scan results in the common issues model
	Issues []ScanIssue `json:"issues"`
}

type ScanIssue struct { // TODO - convert this to a generic type
	// Unique key identifying an issue in the whole result set. Not the same as the Snyk issue ID.
	Id             string `json:"id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	FilePath       string `json:"filePath"`
	AdditionalData any    `json:"additionalData,omitempty"`
}

// Snyk Open Source
type OssIssueData struct {
	License           string         `json:"license,omitempty"`
	Identifiers       OssIdentifiers `json:"identifiers,omitempty"`
	Description       string         `json:"description"`
	Language          string         `json:"language"`
	PackageManager    string         `json:"packageManager"`
	PackageName       string         `json:"packageName"`
	Name              string         `json:"name"`
	Version           string         `json:"version"`
	Exploit           string         `json:"exploit,omitempty"`
	CVSSv3            string         `json:"CVSSv3,omitempty"`
	CvssScore         string         `json:"cvssScore,omitempty"`
	FixedIn           []string       `json:"fixedIn,omitempty"`
	From              []string       `json:"from"`
	UpgradePath       []string       `json:"upgradePath"`
	IsPatchable       bool           `json:"isPatchable"`
	IsUpgradable      bool           `json:"isUpgradable"`
	ProjectName       string         `json:"projectName"`
	DisplayTargetFile string         `json:"displayTargetFile"`
}

type OssIdentifiers struct {
	CWE []string `json:"CWE,omitempty"`
	CVE []string `json:"CVE,omitempty"`
}

type CodeIssueData struct {
	Message            string             `json:"message"`
	LeadURL            string             `json:"leadURL,omitempty"`
	Rule               string             `json:"rule"`
	RuleId             string             `json:"ruleId"`
	RepoDatasetSize    int                `json:"repoDatasetSize"`
	ExampleCommitFixes []ExampleCommitFix `json:"exampleCommitFixes"`
	CWE                []string           `json:"cwe"`
	Text               string             `json:"text"`
	Markers            []Marker           `json:"markers,omitempty"`
	Cols               Point              `json:"cols"`
	Rows               Point              `json:"rows"`
	IsSecurityType     bool               `json:"isSecurityType"`
}

type Point = [2]int

type ExampleCommitFix struct {
	CommitURL string             `json:"commitURL"`
	Lines     []CommitChangeLine `json:"lines"`
}

type CommitChangeLine struct {
	Line       string `json:"line"`
	LineNumber int    `json:"lineNumber"`
	LineChange string `json:"lineChange"`
}

type Marker struct {
	Msg Point            `json:"msg"`
	Pos []MarkerPosition `json:"pos"`
}

type MarkerPosition struct {
	Position
	File string `json:"file"`
}

type Position struct {
	Cols Point `json:"cols"`
	Rows Point `json:"rows"`
}

type CodeActionOptions struct {
	ResolveProvider bool `json:"resolveProvider,omitempty"`
}

type IacIssueData struct {
	PublicId      string   `json:"publicId"`
	Documentation string   `json:"documentation"`
	LineNumber    int      `json:"lineNumber"`
	Issue         string   `json:"issue"`
	Impact        string   `json:"impact"`
	Resolve       string   `json:"resolve,omitempty"`
	Path          []string `json:"path"`
	References    []string `json:"references,omitempty"`
}
