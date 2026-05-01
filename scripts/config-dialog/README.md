# Configuration Dialog Test Script

This directory contains a manual test script for generating and visually inspecting the configuration dialog HTML.

## Usage

Generate the configuration dialog HTML:

```bash
go run scripts/config-dialog/main.go > config_output.html
```

Then open `config_output.html` in your browser to inspect the configuration dialog.

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
