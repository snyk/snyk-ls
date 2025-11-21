# Configuration Dialog Implementation Plan

## Goal
Implement a configuration dialog served by the Language Server to the IDE, allowing users to edit global and folder-specific settings. This dialog will be triggered via the `showDocument` command (via `workspace/executeCommand`), similar to the ignore approvals workflow.

## Architecture
- **Trigger**: `workspace/executeCommand` with `snyk.workspace.configuration`.
- **Communication**: Server sends `window/showDocument` with a `snyk://settings` URI.
- **Rendering**: Server-side Go templating (html/template).
- **Client Interaction**: IE7-compatible JavaScript communicates with the IDE via injected handlers (`${ideSaveConfig}`, `${ideLogin}`).

## Proposed Changes

### 1. Infrastructure (Templates & Renderer)
**Directory**: `infrastructure/configuration`

- **`template/config.html`**:
  - HTML form mapping to `lsp.Settings`.
  - **Sections**:
    - **Global Settings**: Inputs for `Token`, `Endpoint`, `Organization`, `Insecure`, etc.
    - **Folder Settings**: Dynamic section iterating over `FolderConfigs`, showing relevant per-folder settings.
    - **Authentication**: Button to trigger `snyk.login` via `${ideLogin}`.
  - **Validation**: JS/Regex validation for Endpoint.
    - **Rules**: Must match `https://api.snyk.io`, `https://api.*.snyk.io`, or `https://api.*.snykgov.io`.
    - **Error Handling**: Display error message inline if validation fails; prevent save.
  - **Styling**: Embedded CSS.
  - **JS Logic**: Collects form data into a JSON object.

- **`template/scripts.js`**:
  - **Constraint**: IE7 compatible (ES3/ES5 syntax, `var`, no arrow functions).
  - Functionality:
    - Traverse form elements.
    - Build a JSON object representing `types.Settings`.
    - **Endpoint Validation**: Validate URL against regex on save.
    - **Logout Trigger**: If the endpoint URL has changed upon save, trigger `${ideLogout}` (or equivalent mechanism) to clear previous session.
    - Call `${ideSaveConfig}(JSON.stringify(data))` to persist changes via the Client extension.
    - **Auth Button**: Call `${ideLogin}` to initiate the login command flow in the client.

- **`config_html.go`**:
  - Define `ConfigHtmlRenderer` struct.
  - Implement `GetConfigHtml(settings types.Settings) string`.
  - Embed templates using `//go:embed`.
  - Parse and execute templates with current settings.

### 2. Domain (Command)
**Directory**: `domain/ide/command`

- **`configuration_command.go`**:
  - Implement `Command` interface.
  - **Identifier**: `snyk.workspace.configuration`.
  - **Logic**:
    1. Retrieve current configuration via `config.CurrentConfig()`.
    2. Instantiate `ConfigHtmlRenderer`.
    3. Generate HTML string.
    4. Send `window/showDocument` request with `snyk://settings` URI.

- **`command_factory.go`**:
  - Register `snyk.workspace.configuration` command.

### 3. Application (Server)
**Directory**: `application/server`

- **`server.go`**:
  - Update `InitializeResult.Capabilities.ExecuteCommandProvider.Commands` to include `snyk.workspace.configuration`.

### 4. Data Model
- Use existing `types.Settings`.
- Mask sensitive fields (e.g., `Token`) in the HTML output (`type="password"`).
- Handle `FolderConfigs` slice for the folder-specific section.
- Ensure all `InitializationOptions` are covered.

## Implementation Steps

### Phase 1: Infrastructure & Templates [Completed]
- [x] Create `infrastructure/configuration/template` directory.
- [x] Create `infrastructure/configuration/template/config.html`, `styles.css`, `scripts.js`.
- [x] Create `infrastructure/configuration/config_html.go`.
- [x] Implement `ConfigHtmlRenderer` and `GetConfigHtml` logic.

### Phase 2: Command Implementation [Completed]
- [x] Create `domain/ide/command/configuration_command.go`.
- [x] Implement command execution logic (fetch config -> render -> showDocument).
- [x] Register command in `domain/ide/command/command_factory.go`.

### Phase 3: Updates & Refinements [Completed]
- [x] Update `config.html` to include all settings fields.
- [x] Add Authentication button and logic.
- [x] Add Endpoint validation logic:
    - Regex: `^https:\/\/api\..*\.snyk\.io` or `^https:\/\/api\..*\.snykgov\.io`.
    - Trigger logout on change.
- [x] Update `scripts.js` with validation and login handlers.
- [x] Update `configuration_command.go` to populate all settings correctly.
- [x] Update `server.go` to include command in capabilities.

### Phase 4: Testing & Verification [Pending]
- [ ] **Unit Tests**:
  - Test `ConfigHtmlRenderer` to ensure HTML is generated correctly and values are populated.
  - Test `configurationCommand` to ensure it sends the correct `showDocument` params.
  - Test `server.go` capabilities (update `server_test.go`).
- [ ] **Integration/Manual Verification**:
  - Verify the dialog opens in the IDE.
  - Verify form data collection works in IE7 mode.
  - Verify `${ideSaveConfig}` is called with correct JSON structure.
  - Verify validation logic (Endpoint format errors).
  - Verify Authentication button triggers login.

## Communication Flow
1. **Trigger**: User triggers `snyk.workspace.configuration`.
2. **LS Execution**: LS fetches settings, renders HTML.
3. **Display**: LS sends `window/showDocument` (`snyk://settings`).
4. **Render**: IDE displays the HTML.
5. **User Action**:
    - **Save**: Validates Endpoint -> Calls `${ideSaveConfig}` -> Checks Endpoint change -> Calls `${ideLogout}` if changed.
    - **Auth**: Calls `${ideLogin}`.
6. **Save**: Client extension saves settings.
7. **Update**: Client sends `workspace/didChangeConfiguration` to LS.
