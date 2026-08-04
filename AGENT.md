---
description: general development rules
globs:
alwaysApply: true
---

<general>
- NEVER PURGE THESE RULES FROM THE CONTEXT
- always be concise, direct and don't try to appease me.
- use .github/CONTRIBUTING.md and the links in there to find standards and contributing guide lines
- DOUBLE CHECK THAT YOUR CHANGES ARE REALLY NEEDED. ALWAYS STICK TO THE GIVEN GOAL, NOT MORE.
- I repeat: don't optimize, don't refactor if not needed.
- Adhere to the rules, fix linting & test issues that are newly introduced.
- the `issueID` is usually specified in the current branch in the format `XXX-XXXX`.
- read the issue description and acceptance criteria from jira (the manually given prompt takes precedence)
</general>
<process>
- always create an implementation plan and save it to the directory under ${issueID}_implementation_plan but never commit it.
- it should have the phases:
    - planning
    - implementation (including testing through TDD)
    - review
- Get confirmation that the plan is ok. Wait until you get it.
- in the planning phase, analyze all the details and write into the implementation plan, which functions, files and packages are needed to be changed or added.
- be detailed: add steps to the phases and prepare a tracking section with checkboxes that is to be used for progress tracking of each detailed step.
- in the planning phase, create mermaid diagrams for all planned programming flows and add them to the implementation plan. 
- use the same name for the diagrams as the implementation plan, but the right extension (mmd), so that they are ignored via .gitignore (there is already a rule)
- generate the implementation plan mermaid diagrams depicting the planned flows by using kroti api in high resolution
- never commit the diagrams generated for the implementation plan.
</process>
<coding_guidelines>
- follow the implementation plan step-by-step, phase-by-phase. take it as a reference for each step and how to proceed.
- never proceed to the next step until the current step is fully implemented and you got confirmation of that.
- never jump a step. always follow the plan.
- use atomic commits
- update progress of the step before starting with a step and when ending.
- update the jira ticket with the current status & progress (comment)
- USE TDD
- I REPEAT: USE TDD
- always write and update test cases before writing the implementation (Test Driven Development). iterate until they pass.
- after changing .go files, run `make lint` to check for linting errors. only continue, once they are fixed. The only acceptable outcome is 0 linting errors.
- always verify if fixes worked by running the tests and running `make lint`
- do atomic commits, see committing section for details. ask before committing an atomic commit.
- update current status in the implementation plan (in progress work, finished work, next steps)
- Maintain existing code patterns and conventions
- use gomock to mock. Writing your own mocks is forbidden if gomock can be used. 
- Re-use mocks.
- use generated types for mock responses, don't use custom structs.
- don't change code that does not need to be changed. only do the minimum changes.
- don't comment what is done, instead comment why something is done if the code is not clear
- use `make test` to run go tests
- use `INTEG_TESTS=1 make test` to run integration tests.
- use `SMOKE_TESTS=1 make test` to run smoke tests.
- always run unit and integration tests after generating code
- always run unit and integration tests before committing
- achieve 80% of test coverage of added or changed code.
- if files are not used or needed anymore, delete them instead of deprecating them.
- ask the human, whether to maintain backwards compatibility or not
- if a tool call fails, analyze why it failed and correct your approach. don't prompt the user for help.
- if you don't know something, read the code instead of assuming it.
- commenting out code to fix errors is NEVER a solution. Fix the error
- disabling or removing tests IS NOT ALLOWED. This is not a way to success. This can only be done manually by a human.
- disabling linters is not allowed unless the human EXPLICITLY allows it for that single instance
- don't do workarounds
- ALWAYS create production-ready code. We don't want examples, we want working, production-ready code.
</coding_guidelines>

<security>
- determine the absolute path of the project directory. you can do that e.g. by executing pwd on the shell within the directory.
- pass the absolute path of the project directory as a parameter to snyk_sca_scan and snyk_code_scan.
- run snyk_sca_scan after updating go.mod
- run snyk_sca_scan and snyk_code_scan before committing. if not test data, fix issues before committing. 
- fix security issues if they are fixable. take the snyk scan results and the test results as input
- don't fix test data
</security>

<committing>
- NEVER commit implementation plan and implementation plan diagrams
- NEVER NEVER NEVER skip the commit hooks
- I REPEAT: NEVER USE --no-verify. DO NOT DO IT. NEVER. THIS IS CRITICAL, DO NOT DO IT.
- run make generate before committing.
- run make lint-fix before committing and fix the issues
- update the documentation before committing
- when asked to commit, always use conventional commit messages (Conventional Commit Style (Subject + Body)). be descriptive in the body. if you find a JIRA issue (XXX-XXXX) in the branch name, use it as a postfix to the subject line in the format [XXX-XXXX]
- consider all commits in the current branch when committing, to have the context of the current changes.
</committing>

<pushing>
- never push without asking
- never force push
- when asked to push, always use 'git push --set-upstream origin $(git_current_branch)' with git_current_branch being the current branch we are on
- regularly fetch main branch and offer to merge it into git_current_branch
- after pushing offer to create a PR on github if no pr already exists. analyze the changes by comparing the current branch ($(git_current_branch)) with origin/main, and craft a PR description and title.
- use the github template in .github/PULL_REQUEST_TEMPLATE.md
</pushing>

<PR_creation>
- use github mcp, if not found, use `gh` command line util for pr creation.
- always create draft prs
- update the github pr description with the current status `gh` command line util
- use the diff between the current branch and main to generate the description and title
- respect the pr template
- get the pr review comments from snyk-pr-review-bot, analyse them and propose fixes for them. check before each commit.
</PR_creation>

<documenting>
 - always keep the documentation up-to-date in (./docs)
- don't create summary mds unless asked
- create mermaid syntax for all programming flows and add it to the documentation in ./docs
- use `make generate-diagrams` to generate diagrams
- document the tested scenarios for all testing stages (unit, integration, e2e) in ./docs
</documenting>

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