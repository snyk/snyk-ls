# Contributing

## Setup environment

### Private modules

- Add a ssh key to your github profile
- Authorize key for Snyk org SSO
- Update your shell profile, e.g. `~/.zshrc`:

```zsh
export GOPRIVATE="github.com/snyk"
```

- Update your `~/.gitconfig` file, adding:

```
[url "ssh://git@github.com/"]
	insteadOf = https://github.com/
```

- setup commit signing with gpg (only signed commits are allowed)

## Code structure

```
snyk-ls
|- .github            ci/cd workflows
|- .run               run configurations for local development
|- ast                abstract syntax tree for file parsing
|- code               snyk code scan functionality
|- config             language server configuration
|- diagnostics        entry point for all diagnostics, orchestrates start of scans
|- error_reporting    util to report unexpected errors to Sentry
|- iac                snyk iac scan functionality
|- internal           hosting all internal packages, lots of packages will be moved here
|- lsp                types & functions related to the Language Server Protocol
|- oss                snyk open source scan functionality
|- server             json rpc endpoints
|- util               helpers
.goreleaser.yaml      release config to publish binaries
.golangci.yaml        linter config
main.go               entry point for sny-ls
Makefile              build file
```
