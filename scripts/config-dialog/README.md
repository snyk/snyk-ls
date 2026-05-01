# Configuration Dialog Test Script

This directory contains a manual test script for generating and visually inspecting the configuration dialog HTML.

## Usage

Generate a preview for an IDE persona and open it in a browser:

```bash
# Eclipse-style multi-project view
go run scripts/config-dialog/main.go --dummy-data --secrets --integration ECLIPSE > /tmp/preview.html

# Visual Studio single-solution view
go run scripts/config-dialog/main.go --dummy-data --single-folder --integration VISUAL_STUDIO > /tmp/preview.html

# JetBrains zero-folder view
go run scripts/config-dialog/main.go --dummy-data --no-folders --integration JETBRAINS > /tmp/preview.html

open /tmp/preview.html
```

Output is intentionally not committed — regenerate on demand. The JS test fixture
(`js-tests/fixtures/config-page.html`) is the load-bearing artifact and is regenerated
via `make config-dialog-fixture`.

## Customization

Edit `main.go` to customize:

- Integration name (e.g., `VISUAL_STUDIO` vs other IDEs) - affects folder/solution labels
- Token, organization, and other global settings
- Folder configurations and their settings
- Feature flags and severity filters

## What it tests

- Configuration dialog HTML rendering
- Workspace folder filtering (only folders in workspace are shown)
- Visual Studio vs other IDE label differences (Folder vs Solution)
- Folder-specific settings display
- Global settings display
