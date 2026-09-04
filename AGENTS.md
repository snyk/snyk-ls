## Project Overview

**snyk-ls** (`snyk/snyk-ls`) is the Snyk Language Server, a Go implementation of the Language Server Protocol (LSP) that IDE plugins (vscode-extension, snyk-intellij-plugin, snyk-eclipse-plugin, snyk-visual-studio-plugin) embed via stdio/JSON-RPC to run Snyk scans. It integrates Snyk Open Source (SCA), Snyk Code (SAST), Snyk Infrastructure as Code (IaC), and Snyk Secrets. OSS and IaC use the Snyk CLI as a data provider; Code uses the Snyk Code API. It also exposes an MCP server (`mcp_extension/`) and a go-application-framework workflow (`ls_extension/`) that lets the Snyk CLI invoke the language server as an extension.

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

- `main.go` is the entry point: it parses flags, initializes the go-application-framework engine/config, and calls `server.Start(engine, ts)`.
- `application/` handles process wiring: `application/server` (LSP/JSON-RPC handlers), `application/di` (dependency injection), `application/config`, `application/codeaction`, `application/watcher`, `application/entrypoint`.
- `domain/` holds core business logic: `domain/ide` (workspace, hover, codelens, treeview, initialize, all LSP-facing) and `domain/snyk` (scanner, persistence, remediation, delta, for scan orchestration).
- `infrastructure/` contains product/backend integrations: `code`, `oss`, `iac`, `secrets`, `cli` (Snyk CLI executor), `authentication`, `learn`, `analytics`, `snyk_api`, `featureflag`, `filesystem`, `sentry`.
- `internal/` holds shared utilities: `types` (core interfaces/mocks), `product` (product enum), `uri`, `progress`, `notification`, `logging`, `mcp`, `storage`, `vcs`, `fflags`, `testsupport`/`testutil`.
- `ast/` does lightweight source parsing (e.g. `ast/maven/parser.go`) used for range/dependency resolution.
- `ls_extension/` is a go-application-framework workflow letting the Snyk CLI invoke the LS as an extension (`WORKFLOWID_LS`).
- `mcp_extension/` is an MCP server extension exposing Snyk scanning to MCP clients.

## Conventions

- Package-per-concern layout; mocks live in dedicated `mock_*`/`fake_*` files or `mock_<pkg>` subpackages (e.g. `infrastructure/cli/mock_cli/`), generated via `//go:generate ... mockgen` (gomock).
- Table-driven tests with `testify` (`assert`/`require`) are the dominant style.
- `.golangci.yaml` enforces `gofumpt`+`goimports` (local prefix `github.com/snyk/snyk-ls`), `gocyclo` (max 15), `revive`, and a custom `forbidigo` rule requiring config writes go through helpers in `internal/types/config_writers.go` rather than raw resolver key sets.
- Every `.go` file starts with an Apache-2.0 `© <year> Snyk Limited` license header.
- Integration-only code is gated behind the `integration` build tag, matching `INTEG_TESTS`.

## Development Workflow

- Read the Jira issue description/acceptance criteria before starting non-trivial work; update the ticket with a progress comment as you go.
- Never commit an implementation plan or its diagrams to the repo.
- Use gomock for mocking (never hand-written mocks) and reuse existing mocks.
- Run `make lint-fix` and `make generate` (regenerates mocks), then `make test`, before committing; check coverage on changed code (`make test-coverage`, target 80%+).
- Run Snyk SCA/Code scans (`snyk_sca_scan`, `snyk_code_scan`) against the project's absolute path before committing and after `go.mod` changes; fix real findings, don't touch test fixtures.
- Never use `--no-verify` or otherwise skip commit hooks. Use atomic, conventional-commit-style commits; if a Jira ID (`XXX-XXXX`) appears in the branch name, append it to the subject.
- Never push without asking first, and never force-push. Regularly fetch `main` and offer to merge it into the working branch.
- After pushing, offer to open a draft PR using `.github/pull_request_template.md` (or update the existing PR description) with a title/description generated from the diff against `main`.
- Keep `./docs` up to date; document tested scenarios and add Mermaid diagrams for new flows.

## Cursor Cloud specific instructions

Durable, non-obvious notes for agents running in the Cursor Cloud Linux VM. The
update script already runs `go mod download`, so the items below are setup context
and gotchas rather than install steps to repeat.

- **Pin the exact Go patch version.** `go.mod` needs Go 1.26.x, and with
  `GOTOOLCHAIN=auto` Go resolves the toolchain from `go.dev`, which is normally
  outside the egress allowlist. Keep `GOTOOLCHAIN=go1.26.5` set
  (`go env -w GOTOOLCHAIN=go1.26.5`) so it comes from `proxy.golang.org` instead.
- **golangci-lint** is installed by the Makefile via a `curl` from
  `raw.githubusercontent.com`, which is generally reachable here. If that step is
  ever blocked, install the pinned version (`OVERRIDE_GOCI_LINT_V`, currently
  `v2.10.1`) from the module proxy into `.bin/` instead:
  `GOBIN=$(pwd)/.bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.10.1`.
- **Build and lint:** `make build` produces `build/snyk-ls.linux.amd64` and
  `make lint` reports `0 issues`. The binary is an **LSP server speaking JSON-RPC
  over stdio**, so there is no `--help` to inspect: `./build/snyk-ls.linux.amd64 -v`
  prints the version, and exercising it means writing a framed `initialize` request
  to stdin, which returns the server capabilities.
- **Do not run the full `make test` casually.** It carries a ~90 minute timeout, and
  its integration and smoke suites need `SNYK_TOKEN` plus network access, so they
  will not pass in a sandboxed VM. For a quick signal run a unit subset such as
  `go test ./internal/... ./domain/ide/converter/...`. `make test-js` — which
  regenerates the Go HTML fixtures and then runs mocha — passes and needs Node.
- **Node comes from nvm, not `/exec-daemon/node`**, which is first on `PATH` but
  ships no npm. Prepend `PATH="$HOME/.nvm/versions/node/v22.22.3/bin:$PATH"` before
  `make test-js`; nvm is not auto-sourced in non-interactive shells.
- **Probe egress instead of trusting a host list.** The allowlist changes between
  runs, so treat any reachable/blocked list — including in older revisions of this
  section — as stale. Matching is per hostname, and a bare entry is apex-exact
  while `*.example.com` covers subdomains only, so an apex host has to be
  allowlisted in its own right. A block surfaces as a TLS reset mid-handshake
  rather than a DNS failure, so check a host directly before concluding anything:
  `timeout 12 openssl s_client -connect go.dev:443 -servername go.dev </dev/null`.
  The hosts worth probing for this repo are `proxy.golang.org`, `github.com`,
  `raw.githubusercontent.com` and `registry.npmjs.org`.