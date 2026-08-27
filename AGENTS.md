## Project Overview

**snyk-ls** (`snyk/snyk-ls`) is the Snyk Language Server — a Go implementation of the Language Server Protocol (LSP) that IDE plugins (vscode-extension, snyk-intellij-plugin, snyk-eclipse-plugin, snyk-visual-studio-plugin) embed via stdio/JSON-RPC to run Snyk scans. It integrates Snyk Open Source (SCA), Snyk Code (SAST), Snyk Infrastructure as Code (IaC), and Snyk Secrets. OSS and IaC use the Snyk CLI as a data provider; Code uses the Snyk Code API. It also exposes an MCP server (`mcp_extension/`) and a go-application-framework workflow (`ls_extension/`) that lets the Snyk CLI invoke the language server as an extension.

## Build & Development Commands

```bash
make tools               # install golangci-lint, go-licenses, pact, and git hooks
make build                # go build -> build/snyk-ls.<GOOS>.<GOARCH>
make run                  # go run main.go --reportErrors
make test                 # go test -timeout=90m -failfast ./... (+ make test-js)
make test-integ           # alias for INTEG_TESTS=1 make test
make test-smoke           # SMOKE_TESTS=1, all 4 shards
make test-all             # INTEG_TESTS=1 SMOKE_TESTS=1 + all smoke shards
make test-coverage        # adds -cover -coverprofile=build/coverage.out
make test-live PKG=./application/server/ ARGS="-race"   # stream failures as they happen
make lint                 # golangci-lint run ./...
make lint-fix             # go fmt + golangci-lint run --fix
make generate             # go generate ./... (regenerates gomock mocks)
make verify-generate      # fails if `make generate` produces a diff
```

Tests use `testify` with a table-driven style (`tests := []struct{...}`). `INTEG_TESTS=1`/`SMOKE_TESTS=1` (plus `SMOKE_SHARD_1..4`) gate integration/smoke stages inside `make test`.

## Architecture

- `main.go` — entry point: parses flags, initializes the go-application-framework engine/config, calls `server.Start(engine, ts)`.
- `application/` — process wiring: `application/server` (LSP/JSON-RPC handlers), `application/di` (dependency injection), `application/config`, `application/codeaction`, `application/watcher`, `application/entrypoint`.
- `domain/` — core business logic: `domain/ide` (workspace, hover, codelens, treeview, initialize — LSP-facing) and `domain/snyk` (scanner, persistence, remediation, delta — scan orchestration).
- `infrastructure/` — product/backend integrations: `code`, `oss`, `iac`, `secrets`, `cli` (Snyk CLI executor), `authentication`, `learn`, `analytics`, `snyk_api`, `featureflag`, `filesystem`, `sentry`.
- `internal/` — shared utilities: `types` (core interfaces/mocks), `product` (product enum), `uri`, `progress`, `notification`, `logging`, `mcp`, `storage`, `vcs`, `fflags`, `testsupport`/`testutil`.
- `ast/` — lightweight source parsing (e.g. `ast/maven/parser.go`) used for range/dependency resolution.
- `ls_extension/` — go-application-framework workflow letting the Snyk CLI invoke the LS as an extension (`WORKFLOWID_LS`).
- `mcp_extension/` — MCP server extension exposing Snyk scanning to MCP clients.

## Conventions

- Package-per-concern layout; mocks live in dedicated `mock_*`/`fake_*` files or `mock_<pkg>` subpackages (e.g. `infrastructure/cli/mock_cli/`), generated via `//go:generate ... mockgen` (gomock).
- Table-driven tests with `testify` (`assert`/`require`) are the dominant style.
- `.golangci.yaml` enforces `gofumpt`+`goimports` (local prefix `github.com/snyk/snyk-ls`), `gocyclo` (max 15), `revive`, and a custom `forbidigo` rule requiring config writes go through helpers in `internal/types/config_writers.go` rather than raw resolver key sets.
- Every `.go` file starts with an Apache-2.0 `© <year> Snyk Limited` license header.
- Integration-only code is gated behind the `integration` build tag, matching `INTEG_TESTS`.

## Development Workflow

- Read the Jira issue description/acceptance criteria before starting non-trivial work; update the ticket with a progress comment as you go.
- Use TDD: write/update tests before implementation, iterate until green.
- For non-trivial work, write an implementation plan first (planning → implementation → review phases with a progress checklist) and get confirmation before starting; never commit the plan or its diagrams.
- Make the minimum change needed — don't refactor or optimize beyond the stated goal. Comment on *why*, not *what*.
- Use gomock for mocking (never hand-written mocks) and reuse existing mocks.
- Run `make lint-fix` and `make generate` (regenerates mocks), then `make test`, before committing; check coverage on changed code (`make test-coverage`, target 80%+). Never disable a linter or a test to get past this — only a human may do that.
- Run Snyk SCA/Code scans (`snyk_sca_scan`, `snyk_code_scan`) against the project's absolute path before committing and after `go.mod` changes; fix real findings, don't touch test fixtures.
- Never use `--no-verify` or otherwise skip commit hooks. Use atomic, conventional-commit-style commits; if a Jira ID (`XXX-XXXX`) appears in the branch name, append it to the subject.
- Never push without asking first, and never force-push. Regularly fetch `main` and offer to merge it into the working branch.
- After pushing, offer to open a draft PR using `.github/pull_request_template.md` (or update the existing PR description) with a title/description generated from the diff against `main`.
- Keep `./docs` up to date; document tested scenarios and add Mermaid diagrams for new flows.
