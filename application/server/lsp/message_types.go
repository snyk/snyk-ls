/*
 * Copyright 2022 Snyk Ltd.
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
	RootURI               sglsp.DocumentURI        `json:"rootUri,omitempty"`
	ClientInfo            sglsp.ClientInfo         `json:"clientInfo,omitempty"`
	Trace                 sglsp.Trace              `json:"trace,omitempty"`
	InitializationOptions Settings                 `json:"initializationOptions,omitempty"`
	Capabilities          sglsp.ClientCapabilities `json:"capabilities"`

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
	CodeActionProvider               bool                                   `json:"codeActionProvider,omitempty"`
	CodeLensProvider                 *sglsp.CodeLensOptions                 `json:"codeLensProvider,omitempty"`
	DocumentFormattingProvider       bool                                   `json:"documentFormattingProvider,omitempty"`
	DocumentRangeFormattingProvider  bool                                   `json:"documentRangeFormattingProvider,omitempty"`
	DocumentOnTypeFormattingProvider *sglsp.DocumentOnTypeFormattingOptions `json:"documentOnTypeFormattingProvider,omitempty"`
	RenameProvider                   bool                                   `json:"renameProvider,omitempty"`
	ExecuteCommandProvider           *sglsp.ExecuteCommandOptions           `json:"executeCommandProvider,omitempty"`
	SemanticHighlighting             *sglsp.SemanticHighlightingOptions     `json:"semanticHighlighting,omitempty"`
	Workspace                        *Workspace                             `json:"workspace,omitempty"`
}

type Workspace struct {
	WorkspaceFolders *WorkspaceFoldersServerCapabilities `json:"workspaceFolders,omitempty"`
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

// Settings is the struct that is parsed from the InitializationParams.InitializationOptions field
type Settings struct {
	ActivateSnykOpenSource      string `json:"activateSnykOpenSource,omitempty"`
	ActivateSnykCode            string `json:"activateSnykCode,omitempty"`
	ActivateSnykIac             string `json:"activateSnykIac,omitempty"`
	Insecure                    string `json:"insecure,omitempty"`
	Endpoint                    string `json:"endpoint,omitempty"`
	AdditionalParams            string `json:"additionalParams,omitempty"`
	AdditionalEnv               string `json:"additionalEnv,omitempty"`
	Path                        string `json:"path,omitempty"`
	SendErrorReports            string `json:"sendErrorReports,omitempty"`
	Organization                string `json:"organization,omitempty"`
	EnableTelemetry             string `json:"enableTelemetry,omitempty"`
	ManageBinariesAutomatically string `json:"manageBinariesAutomatically,omitempty"`
	CliPath                     string `json:"cliPath,omitempty"`
	Token                       string `json:"token,omitempty"`
	IntegrationName             string `json:"integrationName,omitempty"`
	IntegrationVersion          string `json:"integrationVersion,omitempty"`
	AutomaticAuthentication     string `json:"automaticAuthentication,omitempty"`
	DeviceId                    string `json:"deviceId,omitempty"`
}

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
 * A CodeAction must set either `edit` and/or a `command`. If both are supplied, the `edit` is applied first, then the `command` is executed.
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
	IsPreferred bool `json:"isPreferred,omitempty"`
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
	Edit sglsp.WorkspaceEdit `json:"edit,omitempty"`

	/**
	 * A command this code action executes. If a code action
	 * provides a edit and a command, first the edit is
	 * executed and then the command.
	 */
	Command sglsp.Command `json:"command,omitempty"`

	/**
	 * A data entry field that is preserved on a code action between
	 * a `textDocument/codeAction` and a `codeAction/resolve` request.
	 *
	 * @since 3.16.0
	 */
	Data interface{} `json:"data,omitempty"`
}

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
