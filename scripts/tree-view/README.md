# Tree View Standalone Preview

Generates a standalone HTML file that shows exactly what IDEs would display when
rendering the server-driven tree view. The output is the raw HTML from
`TreeHtmlRenderer.RenderTreeView()` with the `${ideStyle}`, `${ideScript}`, and
`${nonce}` placeholders replaced by demo values — the same replacement each IDE
performs before injecting the HTML into its WebView.

## Usage

```bash
# Via make target (recommended)
make tree-view-preview
open tree_view_output.html

# Or directly
go run scripts/tree-view/main.go > tree_view_output.html
open tree_view_output.html
```

## What it shows

- The full tree hierarchy: folders → products → files → issues
- SVG severity icons (critical/high/medium/low) with color coding
- SVG product icons (Code, OSS, IaC)
- Info nodes: issue counts, fixable messages, "Congrats! No issues found"
- Severity filter toolbar with SVG toggle buttons
- Issue view options (Open/Ignored) filter
- Expand/collapse of all non-leaf nodes (click to toggle)
- Badges: `ignored`, `new`, fixable indicator
- Issue click navigation via a simulated `window.__ideTreeNavigateToRange__` bridge (matches `snyk.navigateToRange` command)
- Dark theme CSS injected via `${ideStyle}` (simulating VS Code Dark+)

## Placeholder simulation

| Placeholder     | Replaced with                                         |
|-----------------|-------------------------------------------------------|
| `${nonce}`      | `demo-nonce-12345`                                    |
| `${ideStyle}`   | Dark theme CSS (simulates VS Code Dark+ injection)    |
| `${ideScript}`  | Console-logging `__ideTreeNavigateToRange__` bridge    |

## Example data

The demo includes issues across all three products:

- **Snyk Code** (3 issues): SQL Injection (critical, fixable), XSS (high), Hardcoded Secret (medium, ignored)
- **Open Source** (3 issues): Prototype Pollution in lodash (high, fixable), DoS in express-fileupload (critical, new), Prototype Pollution in minimist (low)
- **IaC** (2 issues): Container running without root user control (high), Container does not drop all default capabilities (medium)

Two workspace folders are shown: `my-app` (all products) and `shared-lib` (OSS only).

## Customisation

Edit `exampleFolder1Issues()` / `exampleFolder2Issues()` in `main.go` to add/change issues.
Edit `replaceIDEPlaceholders()` to change the simulated IDE theme or bridge behavior.
