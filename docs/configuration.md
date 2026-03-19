# Configuration System

This document describes the complete configuration architecture of the Snyk Language Server (LS), including how settings are registered, stored, resolved, and communicated between the LS and IDE clients.

## Table of Contents

- [Overview](#overview)
- [Configuration Scopes](#configuration-scopes)
- [Prefix Key Storage](#prefix-key-storage)
- [Flag Registration](#flag-registration)
- [Precedence Resolution](#precedence-resolution)
- [Effective Organization](#effective-organization)
- [Remote Configuration (LDX-Sync)](#remote-configuration-ldx-sync)
- [Locked Fields](#locked-fields)
- [IDE ↔ LS Protocol](#ide--ls-protocol)
- [FolderConfig](#folderconfig)
- [Persistence](#persistence)
- [Key Files Reference](#key-files-reference)

---

## Overview

The LS configuration system is built on top of GAF (Go Application Framework) and uses a **flagset-native** approach:

1. **Registration**: All settings are registered as `pflag.FlagSet` flags with annotations for scope, remote key mapping, display name, and IDE key mapping.
2. **Storage**: All values live in a single GAF `Configuration` instance, separated by **prefix keys** (e.g., `user:global:`, `user:folder:<path>:`, `remote:<orgId>:`).
3. **Resolution**: A stateless `ConfigResolver` resolves the effective value for any setting given the setting name, effective org, and folder path, applying scope-specific precedence rules.
4. **Communication**: The LS and IDE exchange settings via `map[string]*ConfigSetting` (keyed by pflag names), supporting both global and per-folder settings.

```mermaid
flowchart LR
    IDE["IDE Client"] -->|"didChangeConfiguration<br/>(ConfigSetting map)"| LS["Language Server"]
    LS -->|"$/snyk.configuration<br/>(ConfigSetting map)"| IDE
    LDX["LDX-Sync API"] -->|"Remote config<br/>(org + machine)"| LS
    LS -->|"Prefix keys"| GAF["GAF Configuration"]
    GAF -->|"Resolve(name, org, folder)"| CR["ConfigResolver"]
```

---

## Terminology

Before diving into the details, here is the vocabulary used consistently throughout this document and the codebase:

| Term | Meaning |
|------|---------|
| **Machine scope** | A setting that applies to the whole LS process — no folder context, no org context. Also called "global" in user-facing strings. |
| **Folder scope** | A setting that is resolved per workspace folder, using the folder's effective org and path as resolution context. |
| **user:global** | The `user:global:<name>` prefix key. Holds values explicitly set by the user that apply machine-wide (e.g., the IDE writes `organization` here). For folder-scope settings it acts as the lowest-priority user-set fallback across all folders. |
| **user:folder** | The `user:folder:<path>:<name>` prefix key. Holds user-set or LS-enriched values for a specific folder (e.g., `base_branch` set by git enrichment, `preferred_org` set by user picking an org for that folder). |
| **remote:machine** | The `remote:machine:<name>` prefix key. Holds machine-scope settings pushed from LDX-Sync by an enterprise admin. |
| **remote:org** | The `remote:<orgId>:<name>` prefix key. Holds org-level folder-scope settings pushed from LDX-Sync. Applies to all folders that resolve to that org. |
| **remote:folder** | The `remote:<orgId>:<folderPath>:<name>` prefix key. Holds per-folder settings pushed from LDX-Sync for a specific repo URL. Takes precedence over remote:org for that folder. |
| **folder metadata** | The `folder:<path>:<name>` prefix key. LS-private bookkeeping facts about a folder (e.g., `auto_determined_org`, `local_branches`). NOT in the GAF resolver chain; never sent to the IDE. Used only internally by the LS. |
| **folder-native setting** | A folder-scope setting stored at `user:folder:` but written automatically by the LS (e.g., `base_branch` from git enrichment). Goes through the full resolver chain and IS sent to the IDE. Source string is `"folder"` because the value reflects the folder's inherent state, not a user preference override. |
| **write-only setting** | A setting accepted from the IDE (IDE→LS) but never included in LS→IDE notifications. Write-only settings participate in normal resolution internally; they are simply omitted from outbound notifications. |
| **source string** | The wire-format string sent in `ConfigSetting.Source` to the IDE: `"default"`, `"global"`, `"folder"`, `"user-override"`, `"ldx-sync"`, `"ldx-sync-locked"`. |

---

## Configuration Scopes

Every setting has a **scope** that determines where it applies and how precedence works:

| Scope | Meaning | Examples | Resolution Context |
|-------|---------|----------|--------------------|
| **Machine** | Applies to the entire LS instance. Equivalent to "global settings" — no folder or org context needed. | `api_endpoint`, `cli_path`, `proxy_http`, `automatic_download` | No folder context |
| **Folder** | Per workspace folder. Resolved with the folder's effective org and path. | `snyk_code_enabled`, `snyk_oss_enabled`, `base_branch`, `preferred_org`, `enabled_severities` | Requires folder path and effective org |

Scope is declared at registration time via the `config.scope` annotation on each pflag flag.

### How `user:global` Relates to Machine vs. Folder Scope

`user:global:<name>` is a single prefix that serves two roles:
- For **machine-scope** settings, it is the primary user-writable layer (overrides remote:machine default, falls back to remote:machine value if not set).
- For **folder-scope** settings, it is the lowest-priority user-set fallback: if a folder has no `user:folder` value and no remote config, the global user value is used. This lets users set a default that applies to all folders unless overridden.

### How `user:folder` Relates to Remote Config

`user:folder:<path>:<name>` entries can be written by:
- The IDE forwarding an explicit user change (e.g., user picks a different org for a folder).
- LS-internal enrichment (e.g., git determines `base_branch = "main"` for a folder and writes it via `SetFolderUserSetting`).

In the precedence chain, `user:folder` wins over `remote:folder` (org-level) and `user:global` unless a locked remote value applies. This means admin-configured remote values can still be overridden by the user unless they are locked.

---

## Prefix Key Storage

All configuration values live in a single GAF `Configuration` instance. Sources are separated by key prefixes. Viper's delimiter is `.`; colons are safe as flat keys.

| Prefix | Format | Purpose | Who writes it |
|--------|--------|---------|---------------|
| `user:global:` | `user:global:<name>` | Machine-wide user values. For machine-scope settings this is the primary user layer. For folder-scope settings it is the lowest-priority user fallback across all folders. | IDE (didChangeConfiguration) |
| `user:folder:` | `user:folder:<path>:<name>` | Per-folder user values and LS-enriched folder state (e.g., git-detected `base_branch`). In the resolver chain this wins over `remote:org` and `user:global` unless a locked remote applies. | IDE (didChangeConfiguration) + LS enrichment |
| `remote:<orgId>:` | `remote:<orgId>:<name>` | Org-level folder-scope values from LDX-Sync. Applies to all folders that resolve to this org. Lower priority than `user:folder`. | LDX-Sync |
| `remote:<orgId>:<path>:` | `remote:<orgId>:<path>:<name>` | Per-repo-URL folder-scope values from LDX-Sync. Higher priority than `remote:<orgId>:`. | LDX-Sync |
| `remote:machine:` | `remote:machine:<name>` | Machine-scope values from LDX-Sync. Lower priority than `user:global` for machine settings. | LDX-Sync |
| `folder:` | `folder:<path>:<name>` | **Folder metadata** — LS-internal, automatically-determined information about a folder (`auto_determined_org`, `local_branches`). Not part of the GAF resolver chain; read directly via `FolderMetadataKey`. Never user-set, never from LDX-Sync. | LS internal (git enrichment, LDX-Sync org detection) |
| *(unprefixed)* | `<name>` | Default values (via `AddDefaultValue`) | Registration time |

> **Folder metadata vs. folder-native settings** — both belong to a folder, but they are fundamentally different:
>
> **Folder metadata** (`folder:` prefix) is LS-private bookkeeping. Examples: `auto_determined_org` (which Snyk org this repo's git remote maps to) and `local_branches` (git branch list). The LS writes these for its own internal use and they never flow through the GAF resolver chain or appear in `$/snyk.configuration` notifications to the IDE.
>
> **Folder-native settings** (`user:folder:` prefix) are ordinary folder-scope settings — they go through the full resolver chain and are sent to the IDE. The difference from other `user:folder:` entries is only semantic: these settings are written by the LS automatically (e.g., git enrichment sets `base_branch = "main"`) rather than always by explicit user action. Because the value reflects the folder's inherent state (not the user overriding an admin default), the wire source string is `"folder"` instead of `"user-override"`.

### Helper Functions

```go
configresolver.UserGlobalKey("snyk_code_enabled")
// → "user:global:snyk_code_enabled"

configresolver.UserFolderKey("/path/to/folder", "snyk_code_enabled")
// → "user:folder:/path/to/folder:snyk_code_enabled"

configresolver.RemoteOrgKey("org-123", "snyk_code_enabled")
// → "remote:org-123:snyk_code_enabled"

configresolver.RemoteMachineKey("api_endpoint")
// → "remote:machine:api_endpoint"

configresolver.FolderMetadataKey("/path/to/folder", "auto_determined_org")
// → "folder:/path/to/folder:auto_determined_org"
```

### IsSet Semantics

- `conf.IsSet(UserGlobalKey(name))` → `true` only if the user explicitly set a global value
- `conf.IsSet(UserFolderKey(folderPath, name))` → `true` only if the user set a folder override
- Defaults are stored via `AddDefaultValue`; `IsSet(name)` is `false` for default-only keys

This distinguishes "user chose X" from "fallback to default."

---

## Flag Registration

All settings are registered via `RegisterAllConfigurations(fs *pflag.FlagSet)` in `internal/types/register_configurations.go`. Each flag carries annotations:

| Annotation | Purpose | Example |
|------------|---------|---------|
| `config.scope` | Setting scope: `machine` or `folder` | `{"machine"}` |
| `config.remoteKey` | LDX-Sync API field name | `{"snyk_code_enabled"}` |
| `config.displayName` | Human-readable label for IDE UI | `{"Snyk Code"}` |
| `config.description` | Description of what the setting does | `{"Enable Snyk Code analysis"}` |
| `config.writeOnly` | Accepted IDE→LS but NOT sent in LS→IDE notifications | `{"true"}` |

> **Write-only settings** (`token`, `send_error_reports`, `enable_snyk_learn_code_actions`, etc.) participate in the normal precedence resolution chain when the LS reads them internally — they are simply skipped when building outbound `$/snyk.configuration` notifications sent to the IDE. This prevents sensitive values (e.g., tokens) from being echoed back.

```go
registerFlag(fs, SettingSnykCodeEnabled, false, "Enable Snyk Code", map[string][]string{
    configresolver.AnnotationScope:       {"folder"},
    configresolver.AnnotationDisplayName: {"Snyk Code Enabled"},
    configresolver.AnnotationDescription: {"Enable Snyk Code security analysis"},
})
```

When `conf.AddFlagSet(fs)` is called, GAF indexes annotations into lookup maps. The `ConfigurationOptions` interface (backed by `ConfigurationOptionsImpl` in `pkg/workflow/configurationoptions.go`) exposes these lookups via the `ConfigurationOptionsMetaData` interface:
- `ConfigurationOptionsByAnnotation("config.scope", "folder")` → all folder-scoped flag names
- `ConfigurationOptionNameByAnnotation("config.remoteKey", "snyk_code_enabled")` → canonical flag name
- `GetConfigurationOptionAnnotation("snyk_code_enabled", "config.scope")` → `"folder"`

### Registered Settings

**Machine scope (29):** `api_endpoint`, `code_endpoint`, `authentication_method`, `proxy_http`, `proxy_https`, `proxy_no_proxy`, `proxy_insecure`, `auto_configure_mcp_server`, `publish_security_at_inception_rules`, `trust_enabled`, `binary_base_url`, `cli_path`, `automatic_download`, `cli_release_channel`, `organization`, `automatic_authentication`, `cli_insecure`, `format`, `device_id`, `offline`, `user_settings_path`, `hover_verbosity`, `client_protocol_version`, `os_platform`, `os_arch`, `runtime_name`, `runtime_version`, `trusted_folders`, `secure_at_inception_execution_frequency`

**Folder scope (25):** `enabled_severities`, `risk_score_threshold`, `cwe_ids`, `cve_ids`, `rule_ids`, `snyk_code_enabled`, `snyk_oss_enabled`, `snyk_iac_enabled`, `snyk_secrets_enabled`, `scan_automatic`, `scan_net_new`, `issue_view_open_issues`, `issue_view_ignored_issues`, `reference_folder`, `reference_branch`, `additional_parameters`, `cli_additional_oss_parameters`, `additional_environment`, `base_branch`, `local_branches`, `preferred_org`, `auto_determined_org`, `org_set_by_user`, `scan_command_config`, `sast_settings`

**Write-only (5):** `token`, `send_error_reports`, `enable_snyk_learn_code_actions`, `enable_snyk_oss_quick_fix_code_actions`, `enable_snyk_open_browser_actions`

---

## Precedence Resolution

The `ConfigResolver` is the single entry point for reading effective configuration values. It is **stateless** — the effective org and folder path are parameters, not internal state.

```go
resolver.GetValue(settingName, folderConfig) → (value, ConfigSource)
resolver.GetBool(settingName, folderConfig) → bool
resolver.IsLocked(settingName, folderConfig) → bool
```

### Machine Scope Precedence

```
Locked Remote > User Global > Remote > Default
```

```mermaid
sequenceDiagram
    participant Caller
    participant Resolver as ConfigResolver
    participant Conf as GAF Configuration

    Caller->>Resolver: Resolve("api_endpoint", org, "")
    Resolver->>Conf: Get(RemoteMachineKey("api_endpoint"))
    alt Remote is locked
        Conf-->>Resolver: RemoteConfigField{Value, IsLocked: true}
        Resolver-->>Caller: value (source: RemoteLocked)
    else
        Resolver->>Conf: Get(UserGlobalKey("api_endpoint"))
        alt User set global value
            Conf-->>Resolver: "https://custom.snyk.io"
            Resolver-->>Caller: value (source: UserGlobal)
        else
            Resolver->>Conf: Get(RemoteMachineKey("api_endpoint"))
            alt Remote has value
                Conf-->>Resolver: RemoteConfigField{Value: "https://app.snyk.io"}
                Resolver-->>Caller: value (source: Remote)
            else
                Resolver->>Conf: Get("api_endpoint")
                Conf-->>Resolver: "" (default)
                Resolver-->>Caller: "" (source: Default)
            end
        end
    end
```

### Folder Scope Precedence

```
Locked Remote (folder) > Locked Remote (org) > User Folder Override > Remote Folder > User Global > Remote Org > Default
```

Folder-scope settings are resolved with both the effective org and folder path. Remote config can be locked at the org level or per remote-URL folder. User folder overrides take priority over unlocked remote org values.

```mermaid
sequenceDiagram
    participant Caller
    participant Resolver as ConfigResolver
    participant Conf as GAF Configuration

    Caller->>Resolver: Resolve("snyk_code_enabled", "org-123", "/workspace/myproject")
    Resolver->>Conf: Get(RemoteOrgFolderKey("org-123", "/workspace/myproject", "snyk_code_enabled"))
    alt Remote folder is locked
        Conf-->>Resolver: RemoteConfigField{Value: true, IsLocked: true}
        Resolver-->>Caller: true (source: RemoteLocked)
    else
        Resolver->>Conf: Get(RemoteOrgKey("org-123", "snyk_code_enabled"))
        alt Remote org is locked
            Conf-->>Resolver: RemoteConfigField{Value: true, IsLocked: true}
            Resolver-->>Caller: true (source: RemoteLocked)
        else
            Resolver->>Conf: Get(UserFolderKey("/workspace/myproject", "snyk_code_enabled"))
            alt User set folder override
                Conf-->>Resolver: LocalConfigField{Value: false, Changed: true}
                Resolver-->>Caller: false (source: UserFolderOverride)
            else
                Resolver->>Conf: Get(RemoteOrgFolderKey("org-123", "/workspace/myproject", "snyk_code_enabled"))
                alt Remote folder has value
                    Conf-->>Resolver: RemoteConfigField{Value: true}
                    Resolver-->>Caller: true (source: Remote)
                else
                    Resolver->>Conf: Get(UserGlobalKey("snyk_code_enabled"))
                    alt User set global value
                        Conf-->>Resolver: true
                        Resolver-->>Caller: true (source: UserGlobal)
                    else
                        Resolver->>Conf: Get(RemoteOrgKey("org-123", "snyk_code_enabled"))
                        alt Remote org has value
                            Conf-->>Resolver: RemoteConfigField{Value: true}
                            Resolver-->>Caller: true (source: Remote)
                        else
                            Resolver-->>Caller: false (source: Default)
                        end
                    end
                end
            end
        end
    end
```

---

## Effective Organization

A workspace can have multiple folders, each associated with a different Snyk organization. The **effective org** for a folder determines which org's remote config (from LDX-Sync) applies.

```mermaid
flowchart TD
    Start["getEffectiveOrg(folderPath)"]
    Check1{"OrgSetByUser == true<br/>AND PreferredOrg != ''?"}
    Check2{"AutoDeterminedOrg != ''?"}
    Check3{"Global Organization != ''?"}
    
    Start --> Check1
    Check1 -->|Yes| UsePreferred["Use PreferredOrg<br/>(user:folder:path:preferred_org)"]
    Check1 -->|No| Check2
    Check2 -->|Yes| UseAuto["Use AutoDeterminedOrg<br/>(folder:path:auto_determined_org)"]
    Check2 -->|No| Check3
    Check3 -->|Yes| UseGlobal["Use Global Org<br/>(user:global:organization)"]
    Check3 -->|No| NoOrg["Empty string<br/>(no org context)"]
```

**Resolution order:**
1. **PreferredOrg** — User explicitly chose an org for this folder (`OrgSetByUser=true` and `PreferredOrg` non-empty)
2. **AutoDeterminedOrg** — LDX-Sync auto-determined an org based on the folder's Git remote URL
3. **Global Organization** — Fallback to the global organization. Reads `UserGlobalKey("organization")` first; if empty, falls back to `configuration.ORGANIZATION` (set by `SetOrganization()` / GAF CLI). This dual-read ensures the global org is found regardless of which code path set it.

---

## Remote Configuration (LDX-Sync)

LDX-Sync is a service that returns organization-level and machine-level configuration policies. Enterprise admins use it to enforce or suggest settings.

### Sync Triggers

```mermaid
sequenceDiagram
    participant IDE
    participant LS as Language Server
    participant LDX as LDX-Sync API
    participant Conf as GAF Configuration

    Note over IDE,Conf: Trigger 1: LSP Initialize
    IDE->>LS: initialize
    LS->>LDX: GetUserConfigForProject (all folders, parallel)
    LDX-->>LS: {settings, organizations, folderSettings}
    LS->>Conf: Write RemoteOrgKey + RemoteMachineKey prefix keys
    LS->>Conf: Write FolderMetadataKey(AutoDeterminedOrg) for folder→org mapping
    LS->>IDE: $/snyk.configuration (resolved settings)

    Note over IDE,Conf: Trigger 2: Workspace Folder Change
    IDE->>LS: workspace/didChangeWorkspaceFolders
    LS->>LDX: GetUserConfigForProject (changed folders)
    LDX-->>LS: config for new folders
    LS->>Conf: Write prefix keys for changed folders
    LS->>IDE: $/snyk.configuration

    Note over IDE,Conf: Trigger 3: User Login
    IDE->>LS: snyk.login
    LS->>LS: Authenticate
    LS->>LDX: GetUserConfigForProject (all folders)
    LDX-->>LS: config
    LS->>Conf: Write all prefix keys (full refresh)
    LS->>IDE: $/snyk.configuration

    Note over IDE,Conf: Trigger 4: Org Change for Folder
    IDE->>LS: didChangeConfiguration (folder org changed)
    LS->>LDX: GetUserConfigForProject (affected folder)
    LDX-->>LS: config for new org
    LS->>Conf: Write prefix keys for affected folder
    LS->>IDE: $/snyk.configuration
```

### Response Processing

Each LDX-Sync response contains:
- **Settings** — machine-scope settings with `value`, `locked`, and `origin`; also org-level values for folder-scoped settings
- **Organizations** — list of orgs with `preferredByAlgorithm` and `isDefault` flags
- **FolderSettings** — per-remote-URL folder-level settings (e.g., `snyk_code_enabled`, `reference_branch`, `reference_folder`)

The adapter writes each response to GAF Configuration via prefix keys:
- **`RemoteOrgKey(orgId, name)`** — stores `RemoteConfigField` for org-level values of folder-scoped settings
- **`RemoteMachineKey(name)`** — stores `RemoteConfigField` for machine-scope settings
- **`RemoteOrgFolderKey(orgId, folderPath, name)`** — stores `RemoteConfigField` for folder-scope settings
- **`FolderMetadataKey(path, AutoDeterminedOrg)`** — stores the auto-determined org ID per folder

### Folder Settings & URL Normalization

The LDX-Sync API response contains a `FolderSettings` map keyed by **normalized** remote URL (e.g., `https://github.com/org/repo`). The backend normalizes all URLs before storage: SCP-style → HTTPS, `.git` stripped, credentials stripped, host+path lowercased.

Since the client reads raw git remote URLs from the local `.git/config` (e.g., `git@github.com:org/repo.git`), the LS normalizes them with `util.NormalizeGitURL` before looking up folder settings in the API response. This ensures SSH, HTTPS, mixed-case, and credentialed URLs all resolve to the same normalized form.

The normalization logic in `internal/util/giturl.go` replicates the backend's `NormalizeGitURL` from `ldx-sync/internal/core/url_normalize.go` to guarantee consistent matching.

See: `docs/diagrams/IDE-1786_folder_settings_flow.mmd`

---

## Locked Fields

When LDX-Sync returns a setting as `locked`, the admin prevents any user override.

### Enforcement Mechanism

```mermaid
sequenceDiagram
    participant LDX as LDX-Sync
    participant LS as Language Server
    participant Conf as GAF Configuration
    participant IDE

    Note over LDX,IDE: On Sync: Clear user overrides for locked fields
    LDX-->>LS: snyk_code_enabled: {value: true, locked: true}
    LS->>Conf: Set(RemoteOrgKey(orgId, "snyk_code_enabled"),<br/>RemoteConfigField{true, IsLocked: true})
    loop For each folder using this org
        LS->>Conf: Unset(UserFolderKey(folderPath, "snyk_code_enabled"))
    end

    Note over LDX,IDE: Between Syncs: Reject locked edits
    IDE->>LS: didChangeConfiguration<br/>{folderConfigs: [{folderPath: "/proj", settings: {snyk_code_enabled: {value: false, changed: true}}}]}
    LS->>LS: validateLockedFields()
    LS->>LS: Check IsLocked("snyk_code_enabled", folderConfig)
    LS-->>IDE: ShowMessage: "Setting locked by organization policy"
    Note over LS: Field value unchanged (still true)

    Note over LDX,IDE: Resolution always returns locked value
    LS->>Conf: Resolve("snyk_code_enabled", orgId, folderPath)
    Conf-->>LS: true (source: RemoteLocked)
```

**Two enforcement points:**
1. **On sync**: User overrides for locked fields are cleared from all folders using that org
2. **Between syncs**: `validateLockedFields()` rejects incoming IDE changes for locked fields

---

## IDE ↔ LS Protocol

### Wire Types

```go
// LS → IDE and IDE → LS (bidirectional)
type ConfigSetting struct {
    Value       any    `json:"value"`
    Changed     bool   `json:"changed,omitempty"`
    Source      string `json:"source,omitempty"`       // see source string table below
    OriginScope string `json:"originScope,omitempty"`  // "tenant", "group", "organization"
    IsLocked    bool   `json:"isLocked,omitempty"`
}

// Top-level config notification
type LspConfigurationParam struct {
    Settings      map[string]*ConfigSetting `json:"settings,omitempty"`
    FolderConfigs []LspFolderConfig         `json:"folderConfigs,omitempty"`
}

// Per-folder config
type LspFolderConfig struct {
    FolderPath FilePath                  `json:"folderPath"`
    Settings   map[string]*ConfigSetting `json:"settings,omitempty"`
}
```

### Source Strings

The `Source` field tells the IDE where the effective value came from:

| Source string | Meaning | Prefix key that won |
|---------------|---------|---------------------|
| `"default"` | No user or remote value; using registered default | *(unprefixed)* |
| `"global"` | User set a machine-wide value | `user:global:` |
| `"folder"` | Value is the folder's authoritative state — either git-enriched metadata (local_branches, auto_determined_org) or a folder-native user setting (base_branch, preferred_org) | `folder:` (metadata) or `user:folder:` (folder-native settings) |
| `"user-override"` | User set a folder-level override of a remotely-configured default | `user:folder:` (non-native settings) |
| `"ldx-sync"` | Remote value from LDX-Sync (not locked; user may override) | `remote:<orgId>:` or `remote:<orgId>:<path>:` |
| `"ldx-sync-locked"` | Remote value from LDX-Sync and locked by admin; cannot be overridden | `remote:<orgId>:` or `remote:<orgId>:<path>:` (locked) |

> **`"folder"` vs `"user-override"`**: Both come from `user:folder:` prefix keys. The distinction is semantic: settings like `base_branch` (set by git enrichment) or `preferred_org` (set by user picking an org for this folder) represent the folder's native state → source `"folder"`. Settings like `snyk_code_enabled` (user explicitly overriding an org default) → source `"user-override"`. The set of folder-native settings is defined by `folderNativeSettings` in `config_resolver.go`.

### The `Changed` Flag

The `Changed` field on `ConfigSetting` controls whether the LS processes a setting. Settings with `Changed: false` (or omitted) are **skipped** — this prevents IDE defaults from overriding ldx-sync or GAF default values.

This applies uniformly to both initialization (`InitializeSettings`) and runtime updates (`UpdateSettings`). The IDE is responsible for setting `Changed: true` only on settings the user explicitly configured.

### IDE → LS Flow (didChangeConfiguration)

```mermaid
sequenceDiagram
    participant IDE
    participant LS as Language Server
    participant CR as ConfigResolver
    participant Conf as GAF Configuration
    participant Store as Persistent Storage

    IDE->>LS: workspace/didChangeConfiguration
    Note over IDE,LS: {settings: {organization: "org-456"},<br/>folderConfigs: [{folderPath: "/proj", settings: {snyk_code_enabled: {value: true, changed: true}, base_branch: {value: "main", changed: true}}}]}

    LS->>LS: processConfigSettings(configResolver)
    LS->>Conf: Set(UserGlobalKey("organization"), "org-456")
    LS->>LS: Apply side effects via ConfigResolver

    LS->>LS: processFolderConfigs(configResolver)
    loop For each folder config
        LS->>LS: validateLockedFields()
        LS->>LS: ApplyLspUpdate(incoming)
        LS->>Conf: Set(UserFolderKey("/proj", "snyk_code_enabled"),<br/>LocalConfigField{Value: true, Changed: true})
        LS->>Conf: Set(UserFolderKey("/proj", "base_branch"),<br/>LocalConfigField{Value: "main", Changed: true})
        LS->>Conf: PersistInStorage(key)
    end

    LS->>Store: Save to XDG storage
```

### LS → IDE Flow ($/snyk.configuration)

```mermaid
sequenceDiagram
    participant LS as Language Server
    participant Resolver as ConfigResolver
    participant CO as ConfigurationOptions
    participant IDE

    LS->>LS: BuildLspConfiguration()
    
    LS->>CO: ConfigurationOptionsByAnnotation("config.scope", "machine")
    CO-->>LS: [api_endpoint, cli_path, proxy_http, ...]
    loop For each machine-scope setting
        LS->>Resolver: GetEffectiveValue(name, nil)
        Resolver-->>LS: EffectiveValue{value, source, originScope}
        Note over LS: Skip writeOnly settings (token, etc.)
        LS->>LS: Build ConfigSetting{value, source, isLocked}
    end

    loop For each workspace folder
        LS->>LS: ToLspFolderConfig()
        loop For each folder-scope setting
            LS->>Resolver: GetEffectiveValue(name, folderConfig)
            Resolver-->>LS: EffectiveValue (resolved for this folder's org)
            LS->>LS: Build ConfigSetting with source, isLocked
        end
    end

    LS->>IDE: $/snyk.configuration<br/>{settings: {...}, folderConfigs: [{folderPath, settings: {...}}]}
```

---

## FolderConfig

`FolderConfig` is a thin wrapper around a folder path, an `Engine`, and a `ConfigResolver`. It holds no setting state — all values are in GAF Configuration prefix keys. The `Engine` provides access to GAF `Configuration`, `Logger`, `NetworkAccess`, and `InvokeWithConfig`.

```go
type FolderConfig struct {
    FolderPath      FilePath
    Engine          workflow.Engine             // GAF engine for configuration, logging, network, workflows
    ConfigResolver  ConfigResolverInterface
    EffectiveConfig map[string]EffectiveValue   // for HTML template display only
}
```

### Accessing Configuration via FolderConfig

```go
// Direct GAF configuration access (preferred for all settings)
conf := folderConfig.Conf()  // returns configuration.Configuration
enabled := conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled))

// Via ConfigResolver (for precedence-aware resolution with folder context)
resolver := folderConfig.ConfigResolver
value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)

// Engine services
logger := folderConfig.Engine.GetLogger()
httpClient := folderConfig.Engine.GetNetworkAccess().GetHttpClient()
```

### Key Operations

- **`Clone()`** — Returns a new `FolderConfig` with the same path and resolver reference
- **`ToLspFolderConfig()`** — Iterates folder-scope pflags via `ConfigurationOptionsByAnnotation("config.scope", "folder")`, resolves each, builds `LspFolderConfig`
- **`ApplyLspUpdate(update)`** — Writes incoming settings to prefix keys using PATCH semantics
- **`Conf()`** — Returns the GAF Configuration via `ConfigResolver.Configuration()`
- **`GetFeatureFlag(flag)`** — Reads feature flag from `FolderMetadataKey(path, "ff_" + flag)`

### Typed Accessors

Typed accessor methods read from `FolderConfigSnapshot` for template/display purposes:

```go
fc.BaseBranch()           // reads from UserFolderKey(path, "base_branch")
fc.PreferredOrg()         // reads from UserFolderKey(path, "preferred_org")
fc.AutoDeterminedOrg()    // reads from FolderMetadataKey(path, "auto_determined_org")
fc.UserOverrides()        // reads all folder-scope UserFolderKey overrides
```

### Folder Config Snapshot

`ReadFolderConfigSnapshot(conf, folderPath)` reads all folder values from configuration into a `FolderConfigSnapshot` struct for comparison and analytics (e.g., detecting org changes, cache clearing).

---

## Persistence

Folder configuration is persisted to XDG-compliant storage using GAF's `PersistInStorage` mechanism.

### Write Path

```mermaid
sequenceDiagram
    participant Caller
    participant Helper as SetFolderUserSetting
    participant Conf as GAF Configuration
    participant Storage as XDG Storage

    Caller->>Helper: SetFolderUserSetting(conf, "/proj", "base_branch", "main")
    Helper->>Conf: key = UserFolderKey("/proj", "base_branch")
    Helper->>Conf: Set(key, LocalConfigField{Value: "main", Changed: true})
    Helper->>Conf: PersistInStorage(key)
    Note over Conf,Storage: GAF persists marked keys to XDG storage on save
```

### Read Path (Startup)

On startup, the folderConfig loader reads persisted folder configurations and injects them back into Configuration:

1. Read folder JSON from XDG storage
2. For each folder path, restore `user:folder:<path>:*` keys (user settings)
3. For each folder path, restore `folder:<path>:*` keys (metadata like `auto_determined_org`, `local_branches`)
4. Enrich `local_branches` from Git if available

### Persistence Helpers

```go
// User settings (stored under UserFolderKey)
SetFolderUserSetting(conf, folderPath, name, value)
// → conf.Set(UserFolderKey(path, name), &LocalConfigField{value, Changed: true})
// → conf.PersistInStorage(key)

// Metadata (stored under FolderMetadataKey)
SetFolderMetadataSetting(conf, folderPath, name, value)
// → conf.Set(FolderMetadataKey(path, name), value)
// → conf.PersistInStorage(key)
```

---

## Infrastructure Layer

The `Config` struct has been fully removed. All infrastructure concerns are handled by standalone functions and dedicated services in `application/config/`:

### Setting Access Pattern

All settings are read/written via GAF Configuration with prefix keys:

```go
// Reading a setting
conf := engine.GetConfiguration()
enabled := conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled))

// Writing a setting
conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
```

### Token Management

Token lifecycle is handled by `TokenServiceImpl` in `application/config/token_service.go`:

```go
type TokenServiceImpl struct {
    scrubbingWriter     zerolog.LevelWriter   // adds token scrub terms to logs
    tokenChangeChannels []chan string          // notifies listeners on token change
    logger              *zerolog.Logger
    m                   sync.RWMutex
}
```

- `SetToken(conf, token)` — writes token to GAF via `WriteTokenToConfig`, sets up log scrubbing, notifies listeners
- `TokenChangesChannel()` — returns a channel for consumers to watch for token changes
- `WriteTokenToConfig(conf, authMethod, token, logger)` — standalone function for GAF token writes (OAuth vs legacy placement)

### Logging

- `SetupLogging(engine, tokenService, server)` — configures the logger with file output and scrubbing writer
- `DisableFileLogging(conf, logger)` — closes log file and clears log path setting
- Package-level `currentLogFile` manages the active log file handle

### Standalone Business Logic Functions

| Function | Responsibility |
|----------|---------------|
| `UpdateApiEndpointsOnConfig(conf, apiUrl)` | Derives API/UI/code URLs from base API URL |
| `SetOrganization(conf, org)` | Redundancy-aware org setting |
| `FolderOrganization(conf, path, logger)` | Effective org for a folder (precedence chain) |
| `ResolveOrgToUUIDWithEngine(engine, org)` | Slug→UUID resolution via GAF |
| `GetFolderConfigFromEngine(engine, resolver, path, logger)` | Folder config retrieval |
| `GetImmutableFolderConfigFromEngine(engine, resolver, path, logger)` | Immutable folder config retrieval |
| `ParseOAuthToken(token, logger)` | OAuth token parsing |
| `IsAnalyticsPermittedForAPI(apiURL)` | Analytics permission check |

### Dependency Flow

```
Entrypoint → engine → server.Start(engine)
  → di.Init(engine) → creates Workspace, ConfigResolver, TokenService, AuthService, Scanner, etc.
  → initHandlers(engine, conf, logger) → handlers close over engine/conf
  → withContext middleware enriches every request context with engine/conf/logger
  → downstream reads from context via EngineFromContext, ConfigurationFromContext, LoggerFromContext
```

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `internal/types/register_configurations.go` | `RegisterAllConfigurations()`, `GetSettingScope`, `IsMachineWideSetting`, `IsFolderScopedSetting` |
| `internal/types/config_resolver.go` | `ConfigResolver` — stateless precedence resolution |
| `internal/types/folder_config.go` | `FolderConfig` — thin wrapper, `ApplyLspUpdate`, `ToLspFolderConfig` |
| `internal/types/folder_config_helpers.go` | `FolderConfigSnapshot`, `SetFolderUserSetting`, `GetSastSettings`, etc. |
| `internal/types/ldx_sync_config.go` | `RemoteConfigField`, `LocalConfigField` wire types; `ConfigSource` is a type alias for `configresolver.ConfigSource` from GAF |
| `internal/types/ldx_sync_adapter.go` | LDX-Sync response conversion, `WriteOrgConfigToConfiguration` |
| `internal/types/lsp.go` | `ConfigSetting`, `LspConfigurationParam`, `LspFolderConfig` wire types |
| `application/server/configuration.go` | `InitializeSettings`, `UpdateSettings`, `processConfigSettings`, `processFolderConfigs` |
| `domain/ide/command/ldx_sync_service.go` | `RefreshConfigFromLdxSync` — parallel fetch + cache update |
| `domain/ide/command/folder_handler.go` | Workspace folder add/remove handling |
| `internal/folderconfig/xdg.go` | XDG-compliant persistence (load/save folder configs) |
| `application/config/config.go` | Standalone business logic functions (`SetOrganization`, `FolderOrganization`, `SetupLogging`, etc.) |
| `application/config/token_service.go` | `TokenServiceImpl` — token lifecycle, scrubbing, change notifications |

### GAF (go-application-framework) Files

| File | Purpose |
|------|---------|
| `pkg/configuration/configresolver/prefix_keys.go` | `UserGlobalKey`, `UserFolderKey`, `RemoteOrgKey`, etc. |
| `pkg/configuration/configresolver/config_fields.go` | `RemoteConfigField`, `LocalConfigField`, `ConfigSource` |
| `pkg/configuration/configresolver/resolver.go` | GAF-level `Resolver` with scope-based precedence |
| `pkg/workflow/configurationoptions.go` | `ConfigurationOptionsMetaData` interface, `ConfigurationOptions`, `ConfigurationOptionsImpl` |
| `pkg/workflow/types.go` | `ConfigurationOptions` interface definition (embeds `ConfigurationOptionsMetaData`) |
