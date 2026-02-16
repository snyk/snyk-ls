# Tree View Standalone Preview

Generates a standalone HTML file that shows exactly what IDEs would display when
rendering the server-driven tree view. The output is the raw HTML from
`TreeHtmlRenderer.RenderTreeView()` with the `${ideStyle}`, `${ideScript}`, and
`${nonce}` placeholders replaced by demo values — the same replacement each IDE
performs before injecting the HTML into its WebView.

## Usage

```bash
go run scripts/tree-view/main.go > tree_view_output.html
open tree_view_output.html
```

## What it shows

- The full tree hierarchy: folders → products → files → issues
- Severity icons (C/H/M/L) with color coding
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

The demo includes 6 issues across two products:

- **Snyk Code** (3 issues): SQL Injection (critical), XSS (high), Hardcoded Secret (medium, ignored)
- **Open Source** (3 issues): Prototype Pollution in lodash (high), DoS in express-fileupload (critical, new), Prototype Pollution in minimist (low)

## Customisation

Edit `exampleIssues()` in `main.go` to add/change issues.
Edit `replaceIDEPlaceholders()` to change the simulated IDE theme or bridge behavior.
