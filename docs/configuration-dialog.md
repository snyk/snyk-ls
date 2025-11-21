# Configuration Dialog Integration Guide

This guide explains how IDEs can integrate with the Snyk Language Server's configuration dialog to provide a user-friendly interface for managing Snyk settings.

## Overview

The configuration dialog is an HTML-based interface that allows users to view and modify all Snyk Language Server settings. The dialog is triggered via an LSP command and displayed in the IDE's webview or browser component.

## Architecture

The configuration dialog follows a client-server pattern:

- **Language Server**: Generates HTML content with current settings, handles configuration updates
- **IDE Client**: Displays the HTML, injects JavaScript functions for user interactions, applies configuration changes

## Integration Flow

### 1. Opening the Configuration Dialog

The IDE triggers the configuration dialog by executing the LSP command `snyk.workspace.configuration`.

**Command Details:**
- **Command**: `workspace/executeCommand`
- **Command ID**: `snyk.workspace.configuration`
- **Arguments**: `[]` (no arguments required)

**Response:**
```
"<html>... full HTML content ...</html>"
```

The command returns the complete HTML content as a string. The IDE can directly display this in a webview without any additional processing.

See [Opening Configuration Dialog Sequence](#opening-configuration-dialog) for the detailed flow.

### 2. Displaying the HTML Content

The IDE should:

1. Execute the command and receive the response
2. Extract the `content` field from the command response
3. Create a webview or browser component
4. Inject IDE-specific JavaScript functions (see [Function Injection](#function-injection))
5. Load the HTML content and display it

**Example (conceptual):**
```typescript
// Execute command and receive HTML
const html = await client.sendRequest('workspace/executeCommand', {
  command: 'snyk.workspace.configuration',
  arguments: []
});

// Create webview and display
const webview = createWebview();
webview.html = injectFunctions(html);
webview.show();
```

### 3. Function Injection

The HTML contains placeholders for IDE-specific functions that must be injected:

| Placeholder | Purpose | Expected Behavior |
|------------|---------|-------------------|
| `${ideLogin}` | Handle authentication | Trigger OAuth or token-based login flow |
| `${ideSaveConfig}` | Save configuration | Receive config data, send to language server |
| `${ideLogout}` | Handle logout | Clear authentication, notify language server |

**Injection Example:**
```typescript
function injectFunctions(html: string): string {
  return html
    .replace('${ideLogin}', 'window.ideLogin')
    .replace('${ideSaveConfig}', 'window.ideSaveConfig')
    .replace('${ideLogout}', 'window.ideLogout');
}

// Expose functions to webview
webview.onDidReceiveMessage(message => {
  switch (message.command) {
    case 'login':
      handleLogin();
      break;
    case 'saveConfig':
      handleSaveConfig(message.data);
      break;
    case 'logout':
      handleLogout();
      break;
  }
});
```

See [Function Injection Flow](#function-injection-flow) for the detailed sequence.

### 4. Saving Configuration

When the user clicks "Save Configuration", the dialog collects all form data and calls `ideSaveConfig(data)`.

**Configuration Data Format:**
```typescript
interface ConfigurationData {
  // Core Authentication
  token?: string;
  endpoint?: string;
  organization?: string;
  automaticAuthentication?: string; // "true" | "false"
  
  // Product Activation
  activateSnykOpenSource?: string;
  activateSnykCode?: string;
  activateSnykIac?: string;
  activateSnykCodeSecurity?: string;
  activateSnykCodeQuality?: string;
  
  // CLI Settings
  cliPath?: string;
  path?: string;
  insecure?: string;
  manageBinariesAutomatically?: string;
  
  // Operational Settings
  sendErrorReports?: string;
  scanningMode?: string; // "auto" | "manual"
  
  // Feature Toggles
  enableSnykLearnCodeActions?: string;
  enableSnykOSSQuickFixCodeActions?: string;
  enableSnykOpenBrowserActions?: string;
  enableDeltaFindings?: string;
  enableTrustedFoldersFeature?: string;
  
  // Advanced Settings
  filterSeverity?: {
    critical?: boolean;
    high?: boolean;
    medium?: boolean;
    low?: boolean;
  };
  issueViewOptions?: {
    openIssues?: boolean;
    ignoredIssues?: boolean;
  };
  
  // Folder-specific settings (dynamic)
  folder_0_folderPath?: string;
  folder_0_baseBranch?: string;
  folder_0_localBranches?: string;
  folder_0_additionalParameters?: string;
  folder_0_referenceFolderPath?: string;
  folder_0_preferredOrg?: string;
  folder_0_riskScoreThreshold?: number;
  
  // Scan command configuration per product per folder
  folder_0_scanConfig_oss_preScanCommand?: string;
  folder_0_scanConfig_oss_preScanOnlyReferenceFolder?: boolean;
  folder_0_scanConfig_oss_postScanCommand?: string;
  folder_0_scanConfig_oss_postScanOnlyReferenceFolder?: boolean;
  
  folder_0_scanConfig_code_preScanCommand?: string;
  folder_0_scanConfig_code_preScanOnlyReferenceFolder?: boolean;
  folder_0_scanConfig_code_postScanCommand?: string;
  folder_0_scanConfig_code_postScanOnlyReferenceFolder?: boolean;
  
  folder_0_scanConfig_iac_preScanCommand?: string;
  folder_0_scanConfig_iac_preScanOnlyReferenceFolder?: boolean;
  folder_0_scanConfig_iac_postScanCommand?: string;
  folder_0_scanConfig_iac_postScanOnlyReferenceFolder?: boolean;
  
  // ... additional folders follow the same pattern with folder_1_, folder_2_, etc.
}
```

**Sending Configuration to Language Server:**

The IDE should send the configuration using the `workspace/didChangeConfiguration` notification:

```typescript
client.sendNotification('workspace/didChangeConfiguration', {
  settings: configData
});
```

**How the Language Server Processes Configuration:**

1. **Receives Notification**: The language server receives the `workspace/didChangeConfiguration` notification
2. **Validates Settings**: Validates all configuration values (e.g., endpoint URLs, numeric ranges)
3. **Applies Configuration**: Updates the active configuration in memory
4. **Persists Settings**: Saves configuration to persistent storage (typically in the user's config directory)
5. **Applies Changes**: Immediately applies changes that affect behavior (e.g., enables/disables products, updates tokens)
6. **Acknowledgment**: The notification is fire-and-forget (no response), but the IDE can verify success by:
   - Monitoring for configuration-related errors via `window/showMessage`
   - Re-executing `snyk.workspace.configuration` to see if changes were applied

**Complete Implementation Example:**

```typescript
async function handleSaveConfig(configData: ConfigurationData) {
  try {
    // 1. Optional: Validate configuration data on IDE side
    if (configData.endpoint && !isValidEndpoint(configData.endpoint)) {
      showError('Invalid endpoint URL');
      return;
    }
    
    // 2. Send configuration to language server
    await client.sendNotification('workspace/didChangeConfiguration', {
      settings: configData
    });
    
    // 3. Provide user feedback
    showMessage('Configuration saved successfully');
    
    // 4. Optional: Refresh the dialog to show updated values
    // await refreshConfigurationDialog();
    
  } catch (error) {
    showError('Failed to save configuration: ' + error.message);
  }
}
```

**Important Notes:**
- The `workspace/didChangeConfiguration` notification is **one-way** (no response expected)
- All settings are optional - only include fields you want to change
- The language server merges provided settings with existing configuration
- Invalid settings are logged but don't fail the entire configuration update
- Sensitive data (tokens) is encrypted when persisted to disk
- Changes take effect immediately after the language server processes them

**Error Handling:**
- Monitor `window/showMessage` notifications for configuration-related errors from the language server
- Validate critical fields (endpoint, paths) on the IDE side before sending
- Provide immediate user feedback for both success and failure cases

See [Saving Configuration Flow](#saving-configuration-flow) for the detailed sequence diagram.

### 5. Authentication Flow

When the user clicks "Authenticate", the dialog calls `ideLogin()`.

**IDE Responsibilities:**
1. Initiate OAuth or token-based authentication
2. On success, update the token in the webview (if needed)
3. Notify the language server of the new authentication state

**Example:**
```typescript
async function handleLogin() {
  try {
    const token = await authenticateWithSnyk();
    
    // Update language server
    await client.sendNotification('workspace/didChangeConfiguration', {
      settings: { token }
    });
    
    // Optionally, refresh the dialog to show authenticated state
    await refreshConfigurationDialog();
  } catch (error) {
    showError('Authentication failed: ' + error.message);
  }
}
```

See [Authentication Flow](#authentication-flow) for the detailed sequence.

### 6. Logout Flow

When the user clicks "Logout", the dialog calls `ideLogout()`.

**IDE Responsibilities:**
1. Clear stored authentication credentials
2. Execute the logout command on the language server
3. Update UI to reflect logged-out state

**Example:**
```typescript
async function handleLogout() {
  try {
    // Execute logout command
    await client.sendRequest('workspace/executeCommand', {
      command: 'snyk.logout',
      arguments: []
    });
    
    // Clear local credentials
    await clearStoredCredentials();
    
    // Optionally, refresh the dialog
    await refreshConfigurationDialog();
  } catch (error) {
    showError('Logout failed: ' + error.message);
  }
}
```

See [Logout Flow](#logout-flow) for the detailed sequence.

## Sequence Diagrams

### Opening Configuration Dialog

![Opening Configuration Dialog](images/configuration-dialog-open.png)

```mermaid
sequenceDiagram
    participant IDE as IDE Client
    participant LSP as Language Server
    participant Config as Config System
    participant HTML as HTML Renderer
    
    IDE->>LSP: workspace/executeCommand<br/>{command: "snyk.workspace.configuration"}
    
    LSP->>Config: Get current configuration
    Config-->>LSP: Configuration data
    
    LSP->>Config: Construct Settings from Config
    Config-->>LSP: Settings object
    
    LSP->>HTML: Generate HTML with settings
    HTML-->>LSP: HTML content
    
    LSP-->>IDE: Command response<br/>{uri: "snyk://settings", content: "<html>..."}
    
    IDE->>IDE: Extract HTML from response
    IDE->>IDE: Create webview
    IDE->>IDE: Inject IDE functions
    IDE->>IDE: Display HTML in webview
```

### Function Injection Flow

![Function Injection Flow](images/configuration-dialog-injection.png)

```mermaid
sequenceDiagram
    participant IDE as IDE Client
    participant Webview as Webview Component
    participant HTML as HTML Content
    
    IDE->>IDE: Receive HTML content
    
    Note over IDE: Replace placeholders with<br/>actual function names
    IDE->>IDE: html.replace('${ideLogin}', 'window.ideLogin')
    IDE->>IDE: html.replace('${ideSaveConfig}', 'window.ideSaveConfig')
    IDE->>IDE: html.replace('${ideLogout}', 'window.ideLogout')
    
    IDE->>Webview: Load modified HTML
    
    IDE->>Webview: Expose functions:<br/>- window.ideLogin()<br/>- window.ideSaveConfig(data)<br/>- window.ideLogout()
    
    Webview-->>IDE: Webview ready
    
    Note over HTML,Webview: User interacts with dialog
    
    HTML->>Webview: User clicks "Authenticate"
    Webview->>IDE: Call window.ideLogin()
    IDE->>IDE: Handle authentication
    
    HTML->>Webview: User clicks "Save"
    Webview->>Webview: collectData()
    Webview->>IDE: Call window.ideSaveConfig(data)
    IDE->>IDE: Handle save
    
    HTML->>Webview: User clicks "Logout"
    Webview->>IDE: Call window.ideLogout()
    IDE->>IDE: Handle logout
```

### Saving Configuration Flow

![Saving Configuration Flow](images/configuration-dialog-save.png)

```mermaid
sequenceDiagram
    participant User as User
    participant Dialog as Configuration Dialog
    participant Webview as Webview
    participant IDE as IDE Client
    participant LSP as Language Server
    participant Config as Config System
    
    User->>Dialog: Modify settings
    User->>Dialog: Click "Save Configuration"
    
    Dialog->>Dialog: collectData()<br/>Gather all form values
    
    Dialog->>Webview: Call window.ideSaveConfig(data)
    
    Webview->>IDE: Post message with config data
    
    IDE->>IDE: Validate configuration data
    
    IDE->>LSP: workspace/didChangeConfiguration<br/>{settings: data}
    
    LSP->>Config: Update configuration
    Config->>Config: Validate settings
    Config->>Config: Apply settings
    Config->>Config: Persist to storage
    Config-->>LSP: Configuration updated
    
    LSP-->>IDE: Acknowledgment
    
    IDE->>Webview: Show success message
    Webview->>Dialog: Display "Configuration saved"
    Dialog->>User: Visual feedback
```

### Authentication Flow

![Authentication Flow](images/configuration-dialog-auth.png)

```mermaid
sequenceDiagram
    participant User as User
    participant Dialog as Configuration Dialog
    participant IDE as IDE Client
    participant Auth as Auth Service
    participant LSP as Language Server
    participant Snyk as Snyk API
    
    User->>Dialog: Click "Authenticate"
    Dialog->>IDE: Call window.ideLogin()
    
    IDE->>Auth: Initiate authentication
    
    alt OAuth Flow
        Auth->>Snyk: Request OAuth authorization
        Snyk-->>User: Open browser with auth page
        User->>Snyk: Approve authorization
        Snyk->>Auth: OAuth callback with code
        Auth->>Snyk: Exchange code for token
        Snyk-->>Auth: Access token
    else Token Authentication
        Auth->>User: Prompt for API token
        User->>Auth: Provide token
    end
    
    Auth-->>IDE: Authentication successful<br/>{token: "..."}
    
    IDE->>LSP: workspace/didChangeConfiguration<br/>{settings: {token: "..."}}
    
    LSP->>Snyk: Verify token
    Snyk-->>LSP: Token valid
    
    LSP-->>IDE: Configuration updated
    
    IDE->>Dialog: Refresh with authenticated state
    Dialog->>User: Show "Authenticated" status
```

### Logout Flow

![Logout Flow](images/configuration-dialog-logout.png)

```mermaid
sequenceDiagram
    participant User as User
    participant Dialog as Configuration Dialog
    participant IDE as IDE Client
    participant LSP as Language Server
    participant Auth as Auth Service
    participant Storage as Credential Storage
    
    User->>Dialog: Click "Logout"
    Dialog->>IDE: Call window.ideLogout()
    
    IDE->>LSP: workspace/executeCommand<br/>{command: "snyk.logout"}
    
    LSP->>Auth: Clear authentication state
    Auth->>Storage: Remove credentials
    Storage-->>Auth: Credentials cleared
    Auth-->>LSP: Logout complete
    
    LSP-->>IDE: Command completed
    
    IDE->>IDE: Clear local token storage
    
    IDE->>Dialog: Refresh with logged-out state
    Dialog->>User: Show "Not authenticated" status
```

## Implementation Checklist

### Basic Integration
- [ ] Execute `snyk.workspace.configuration` command
- [ ] Extract HTML content from command response
- [ ] Create webview/browser component for display
- [ ] Inject `ideLogin`, `ideSaveConfig`, `ideLogout` functions
- [ ] Display HTML content in webview

### Configuration Management
- [ ] Parse configuration data from dialog
- [ ] Send `workspace/didChangeConfiguration` notification
- [ ] Validate configuration data before sending
- [ ] Handle configuration errors gracefully
- [ ] Provide user feedback on save success/failure

### Authentication
- [ ] Implement `ideLogin()` function
- [ ] Support OAuth flow (recommended)
- [ ] Support token-based authentication (fallback)
- [ ] Update language server on successful authentication
- [ ] Handle authentication errors

### Logout
- [ ] Implement `ideLogout()` function
- [ ] Execute `snyk.logout` command
- [ ] Clear stored credentials
- [ ] Update UI to reflect logged-out state

### User Experience
- [ ] Display loading indicators during operations
- [ ] Show success/error messages
- [ ] Provide validation feedback for form fields
- [ ] Support dialog refresh after configuration changes
- [ ] Handle dialog close/cancel actions

## Best Practices

1. **Error Handling**: Always wrap LSP calls in try-catch blocks and provide meaningful error messages to users.

2. **Validation**: Validate configuration data on the IDE side before sending to the language server.

3. **Security**: 
   - Never log or expose authentication tokens
   - Use secure credential storage
   - Clear sensitive data on logout

4. **User Feedback**: Provide immediate visual feedback for all user actions (save, authenticate, logout).

5. **Refresh Strategy**: After authentication or logout, consider refreshing the dialog to show the updated state.

6. **Webview Isolation**: Use proper webview security settings to isolate the dialog from other IDE components.

## Troubleshooting

### Dialog doesn't open
- Verify the command ID is correct: `snyk.workspace.configuration`
- Check that the language server is initialized
- Ensure `workspace/executeCommand` capability is supported

### Functions not working
- Verify function injection is replacing all placeholders
- Check that webview message passing is configured correctly
- Ensure functions are exposed to the webview's global scope

### Configuration not saving
- Verify the `workspace/didChangeConfiguration` notification format
- Check that the language server has `workspace.configuration` capability
- Validate configuration data structure

### Authentication fails
- Ensure network connectivity to Snyk API
- Verify OAuth redirect URLs are configured correctly
- Check that the token is valid and not expired

## Related Documentation

- [LSP Specification](https://microsoft.github.io/language-server-protocol/)
- [Snyk API Documentation](https://docs.snyk.io/snyk-api-info)
- [Configuration Settings Reference](./configuration-settings.md)

## Support

For issues or questions about the configuration dialog integration:
- Open an issue on [GitHub](https://github.com/snyk/snyk-ls/issues)
- Join the discussion in [Snyk Community](https://community.snyk.io/)

