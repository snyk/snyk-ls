# IDE-1226: Create Release Compatibility Matrix

## Overview
Create a compatibility matrix that surfaces the latest compatible CLI version for each IDE plugin version.

## Requirements
1. Matrix containing all IDE plugins released in the past 12 months
2. Surface the latest compatible CLI version for each IDE plugin version
3. Sort by descending order of release date
4. Automatically refresh with each release/daily
5. Automatically surface the matrix in public documentation

## IDE Plugin Repositories to Monitor
- https://github.com/snyk/snyk-intellij-plugin
- https://github.com/snyk/snyk-visual-studio-plugin
- https://github.com/snyk/snyk-eclipse-plugin
- https://github.com/snyk/vscode-extension

## Implementation Plan

### Phase 1: Create Core Functionality
1. **Create a script to retrieve GitHub releases**
   - Fetch releases from GitHub API for each IDE plugin repository
   - Filter releases from the past 12 months
   - Handle pagination for large number of releases
   
2. **Extract required protocol version from each IDE plugin release**
   - For each release tag, checkout the IDE plugin code
   - Find where the required protocol version is defined in each plugin
   - Store the mapping of plugin version -> required protocol version

3. **Map protocol version to CLI version**
   - Use the Snyk API endpoint to get CLI version for each protocol version
   - URL pattern: `https://downloads.snyk.io/cli/preview/ls-protocol-version-{version}`
   - Determine the latest compatible CLI version for each protocol version

4. **Generate the compatibility matrix**
   - Create a structured output (markdown table)
   - Sort by release date (descending)
   - Include: Release date, IDE plugin (name + version), Latest Compatible CLI version

### Phase 1.5: Enhance with CLI Version Range Support
1. **Clone and analyze Snyk CLI repository**
   - Clone github.com/snyk/cli temporarily
   - Get all releases from the past 12+ months
   - For each CLI release, extract the snyk-ls dependency from go.mod
   
2. **Extract protocol version from snyk-ls commits**
   - For each CLI release, get the snyk-ls commit hash from go.mod
   - Clone/cache snyk-ls repository
   - Check out the specific commit and extract its protocol version
   - Build a mapping: CLI version -> protocol version

3. **Calculate compatible CLI ranges**
   - For each IDE plugin's required protocol version
   - Find all CLI versions that use the same protocol version
   - Display as a range (e.g., "v1.1290.0 - v1.1298.0")
   - Rename column to "Compatible CLIs"

### Phase 2: Automation
1. **Create GitHub Action workflow that updates the documentation**   
   - run daily to maintain 12-month window
   - Execute the compatibility matrix script

2. **Update documentation**
   - Clone the user docs repo at github.com/snyk/user-docs
   - Update a dedicated compatibility matrix file compability-matrix.md under /docs/cli-ide-and-ci-cd-integrations/
   - Create a PR to the user docs repository (github.com/snyk/user-docs) to submit the file using the gh cli tool

### Phase 3: Testing and Validation
1. **Unit tests for the script**
   - Test GitHub API integration
   - Test version extraction logic for each IDE plugin type
   - Test matrix generation

2. **Integration tests**
   - Test the full workflow
   - Validate the output format

## Technical Details

### Script Structure
```
scripts/
  compatibility-matrix/
    main.go
    main_test.go
    plugins.go          # Plugin-specific extraction logic
    github.go           # GitHub API interactions
    cli_version.go      # CLI version mapping
```

### Data Flow
1. GitHub API → Releases for each IDE plugin (past 12 months)
2. For each release → Clone/checkout tag → Extract required protocol version
3. Protocol version → Query Snyk API for latest compatible CLI version
4. Generate markdown table
5. Create/Update compatibility-matrix.md
6. Create PR to docs repo

### Expected Protocol Version Locations
- **IntelliJ**: Look for required protocol version in source
- **Visual Studio**: Look for required protocol version in source
- **Eclipse**: Look for required protocol version in source
- **VSCode**: Look for required protocol version in source

### GitHub Action Workflow
```yaml
name: Update Compatibility Matrix
on:
  release:
    types: [published]
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:      # Manual trigger
```

## Example Output
```markdown
| Release Date | IDE Plugin | Latest Compatible CLI Version |
|--------------|------------|---------------------|
| 2025-05-16 | VSCode 2.2.0 | 1.1297.0 |
| 2025-05-16 | Visual Studio 2.1.0 | 1.1297.0 |
| 2025-05-15 | IntelliJ 3.4.2 | 1.1295.0 |
| 2025-05-14 | Eclipse 1.8.0 | 1.1290.0 |
```

## Questions to Resolve
1. Where exactly is the required protocol version stored in each IDE plugin?
2. Should we cache the results to avoid excessive GitHub API calls? yes