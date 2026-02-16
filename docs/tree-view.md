## Server-Driven HTML Tree View

The tree view displays Snyk scan results in a hierarchical panel rendered as an HTML web view inside each IDE. The HTML is produced entirely by snyk-ls using Go `html/template`, following the same pattern as the scan summary and configuration dialog.

### Architecture

```mermaid
graph TB
    subgraph LS["snyk-ls (Language Server)"]
        SC[Scan Pipeline]
        TB[TreeBuilder]
        TR[TreeHtmlRenderer]
        TE[TreeViewEmitter / TreeScanStateEmitter]
        CMD[Commands: getTreeView, getTreeViewIssueChunk, toggleTreeFilter]
    end

    subgraph IDE["IDE (VS Code / IntelliJ / VS / Eclipse)"]
        WV[WebView Panel]
        BR["JS-IDE Bridge (window.__ideTreeXxx__)"]
    end

    SC -->|scan results| TB
    TB -->|TreeViewData| TR
    TR -->|HTML string| TE
    TE -->|"$/snyk.treeView notification"| WV
    CMD -->|HTML string| WV
    WV --> BR
    BR -->|"workspace/executeCommand"| CMD
```

### Tree Hierarchy

The tree follows a four-level hierarchy:

1. **Folder** (only for multi-root workspaces)
2. **Product** (Snyk Code, Snyk Open Source, Snyk IaC)
3. **File** (relative path, issue count)
4. **Issue** (title, severity icon, badges for ignored/new/fixable)

### Packages and Files

| File | Purpose |
|------|---------|
| `domain/ide/treeview/tree_node.go` | `TreeNode`, `TreeViewData`, `TreeViewFilterState` types |
| `domain/ide/treeview/tree_builder.go` | Builds tree hierarchy from workspace issue data |
| `domain/ide/treeview/tree_html.go` | Renders `TreeViewData` into HTML using `html/template` |
| `domain/ide/treeview/tree_emitter.go` | Sends `$/snyk.treeView` notifications |
| `domain/ide/treeview/tree_scan_emitter.go` | Adapts scan state changes to tree view updates |
| `domain/ide/treeview/template/tree.html` | HTML template with filter toolbar and tree nodes |
| `domain/ide/treeview/template/styles.css` | IE11-compatible CSS |
| `domain/ide/treeview/template/tree.js` | ES5 expand/collapse, lazy-loading, filter toggle handlers |
| `domain/ide/command/get_tree_view.go` | `snyk.getTreeView` command (on-demand full HTML) |
| `domain/ide/command/get_tree_view_issue_chunk.go` | `snyk.getTreeViewIssueChunk` command (paginated issues) |
| `domain/ide/command/toggle_tree_filter.go` | `snyk.toggleTreeFilter` command (severity/issueView toggles) |
| `domain/ide/treeview/template/js-tests/` | JSDOM-based JS runtime tests for `tree.js` (run via `make test-js`) |
| `application/server/server_smoke_treeview_test.go` | Smoke tests for tree view commands and notifications |

### LSP Commands

#### `snyk.getTreeView`

Returns the full tree view HTML. Used for initial load or manual refresh.

**Arguments:** none

**Returns:** HTML string

#### `snyk.getTreeViewIssueChunk`

Returns a paginated chunk of issue nodes for a specific file and product.

**Arguments:** `[{ filePath: string, product: string, range: { start: number, end: number } }]`

**Returns:** `{ issueNodesHtml: string, totalFileIssues: number, hasMore: boolean, nextStart: number }`

#### `snyk.toggleTreeFilter`

Toggles a filter setting and returns re-rendered tree HTML.

**Arguments:** `[filterType: string, filterValue: string, enabled: boolean]`

- `filterType`: `"severity"` or `"issueView"`
- `filterValue`: for severity: `"critical"`, `"high"`, `"medium"`, `"low"`; for issueView: `"openIssues"`, `"ignoredIssues"`
- `enabled`: `true` to enable, `false` to disable

**Returns:** HTML string (updated tree)

### LSP Notification

#### `$/snyk.treeView`

Pushed whenever scan results change. Payload:

```json
{
  "treeViewHtml": "<html>...</html>",
  "totalIssues": 42
}
```

### JS-IDE Bridge Functions

The tree view HTML includes `${ideScript}` placeholder for IDE-specific bridge code. IDEs implement these `window` functions:

| Function | Purpose |
|----------|---------|
| `window.__ideTreeNavigateToRange__(filePath, range)` | Navigate to range in file — maps to `snyk.navigateToRange` command |
| `window.__ideTreeToggleFilter__(filterType, filterValue, enabled)` | Toggle filter via `snyk.toggleTreeFilter` command |
| `window.__ideTreeRequestIssueChunk__(requestId, filePath, product, start, end)` | Request paginated issues via `snyk.getTreeViewIssueChunk` |
| `window.__onIdeTreeIssueChunk__(requestId, payload)` | Callback for received issue chunks |

#### `__ideTreeNavigateToRange__` Details

The `range` argument matches the `snyk.navigateToRange` command's second argument:

```json
{
  "start": { "line": 10, "character": 4 },
  "end": { "line": 15, "character": 20 }
}
```

The IDE bridge implementation should forward the call as:

```
workspace/executeCommand("snyk.navigateToRange", [filePath, range])
```

The LS handles this by sending `window/showDocument` back to the IDE with the file URI and selection range.

### Filter Architecture

```mermaid
sequenceDiagram
    participant User
    participant WebView
    participant IDE
    participant LS

    User->>WebView: Click severity button "High"
    WebView->>WebView: JS: read data-filter-type, data-filter-value
    WebView->>IDE: window.__ideTreeToggleFilter__("severity", "high", false)
    IDE->>LS: workspace/executeCommand snyk.toggleTreeFilter ["severity", "high", false]
    LS->>LS: Update Config.SetSeverityFilter
    LS->>IDE: Return re-rendered tree HTML
    IDE->>WebView: Replace tree content
```

### Issue Sorting

Issues are sorted by `sortIssuesByPriority` which uses a weighted formula:
1. Severity (Critical > High > Medium > Low)
2. Product-specific score (`GetScore()` from `IssueAdditionalData`)
3. Issue ID as tie-breaker

### Build & Test

The `Makefile` includes dedicated targets:

- `make test` — runs JS tests (`test-js`) first, then all Go tests
- `make test-js` — runs the JSDOM-based JS runtime tests with `--experimental-test-coverage`
- `SMOKE_TESTS=1 make test -run Test_SmokeTreeView` — runs the end-to-end smoke tests against a real Snyk backend

### Performance

- **Collapsed by default**: file nodes start collapsed; issues load on expand
- **Lazy loading**: `snyk.getTreeViewIssueChunk` fetches issues in pages of 100
- **Auto-expand**: trees with <= 50 total issues auto-expand progressively

### IE11 Compatibility

All JS is ES5 (no arrow functions, no `const`/`let`, no template literals). CSS uses no variables, no grid, no `:focus-visible`. The `<meta http-equiv='X-UA-Compatible' content='IE=edge' />` tag is included.

### Test Scenarios

**Unit tests (`make test`):**
- Tree builder: empty, single, multi-folder, filtered, sorted, TotalIssues computation
- HTML renderer: valid output, node rendering, filter toolbar, lazy-load attributes, issue chunks
- Emitter: notification sent, TotalIssues propagated
- Commands: getTreeView, getTreeViewIssueChunk, toggleTreeFilter (severity + issueView + error cases)

**JS runtime tests (`make test-js`, also run as part of `make test`):**

Located in `domain/ide/treeview/template/js-tests/tree-runtime.test.mjs`. These use JSDOM to execute `tree.js` in a browser-like environment and verify all interactive behaviors:

| Test | Covers |
|------|--------|
| auto-expand under threshold | `expandFileNodesInChunks`, `ensureExpanded`, `maybeLoadIssuesForFileNode` |
| no auto-expand over threshold | threshold guard branch (> 50 issues) |
| load-more click | `findAncestor`, `parseIntSafe`, append chunk request |
| expand/collapse toggle | click handler toggle logic, `findChildrenContainer` |
| issue node click → navigation | `__ideTreeNavigateToRange__` bridge with structured range object |
| filter active → toggle off | filter toolbar click with `filter-active` class, `enabled=false` |
| filter inactive → toggle on | filter toolbar click without `filter-active`, `enabled=true` |
| chunk callback injects HTML | `__onIdeTreeIssueChunk__`, `clearLoadingRow`, attribute updates |
| chunk with hasMore | `data-next-start` attribute set |
| already-loaded skip | `maybeLoadIssuesForFileNode` early return when `data-issues-loaded="true"` |
| string payload parsing | JSON.parse branch in `__onIdeTreeIssueChunk__` |

Run JS tests standalone: `make test-js`

**Smoke tests (`SMOKE_TESTS=1 make test -run Test_SmokeTreeView`):**

Located in `application/server/server_smoke_treeview_test.go`. These run against a real Snyk backend using the `nodejs-goof` test repository:

| Test | Covers |
|------|--------|
| tree view notification received after scan | `$/snyk.treeView` notification emitted with valid HTML and `TotalIssues > 0` |
| getTreeView command returns HTML | `snyk.getTreeView` returns full HTML with product nodes and file nodes |
| toggleTreeFilter disables low severity | `snyk.toggleTreeFilter` toggles severity filter and returns re-rendered HTML |
| getTreeViewIssueChunk returns issues | `snyk.getTreeViewIssueChunk` returns paginated issues with HTML fragment |
