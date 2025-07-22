# IDE Plugin Compatibility Matrix Generator

This tool generates a compatibility matrix showing the latest compatible CLI version for each IDE plugin version.

## Overview

The compatibility matrix generator:
- Fetches releases from all Snyk IDE plugin repositories (VSCode, IntelliJ, Visual Studio, Eclipse)
- Extracts the required protocol version from each release
- Maps protocol versions to latest compatible CLI versions
- Generates a markdown table sorted by release date

## Usage

### Basic Usage

```bash
# Generate matrix and write to default output file
go run .

# Dry run - print to stdout
go run . -dry-run

# Custom output file
go run . -output custom-matrix.md

# Custom cache directory
go run . -cache /tmp/matrix-cache

# Look back different number of months
go run . -months 6
```

### Building

```bash
go build -o compatibility-matrix .
```

## How It Works

1. **Fetch Releases**: Uses GitHub API to fetch releases from each IDE plugin repository
2. **Extract Protocol Version**: Downloads source archives and extracts the required protocol version using plugin-specific patterns
3. **Map to CLI Version**: Queries Snyk API to find the latest compatible CLI version for each protocol version
4. **Generate Matrix**: Creates a markdown table with all the information

## Caching

The tool implements caching to avoid excessive API calls:
- GitHub release data is cached for 7 days
- CLI version mappings are cached for 24 hours
- Cache is stored in `.cache/compatibility-matrix/` by default

## GitHub Action

The tool is run daily by a GitHub Action that:
1. Generates the compatibility matrix
2. Creates a PR to the `snyk/user-docs` repository
3. Updates `/docs/cli-ide-and-ci-cd-integrations/compatibility-matrix.md`

## Environment Variables

- `GITHUB_TOKEN`: Optional GitHub token for higher API rate limits

## Protocol Version Locations

Each IDE plugin stores the required protocol version differently:

- **VSCode**: `PROTOCOL_VERSION` constant in TypeScript files
- **IntelliJ**: Protocol version in Kotlin/Java files
- **Visual Studio**: Protocol version in C# files or JSON configuration
- **Eclipse**: Protocol version in Java files or manifest

## Testing

Run tests with:

```bash
go test -v
```

## Troubleshooting

- If protocol version extraction fails, check the regex patterns in `plugins.go`
- For API rate limits, set `GITHUB_TOKEN` environment variable
- Check cache directory permissions if caching fails 