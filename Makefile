# Copyright 2022 Snyk Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# project variables
PROJECT_NAME := snyk-ls

# build variables
.DEFAULT_GOAL = test
BUILD_DIR := build
DEV_GOARCH := $(shell go env GOARCH)
DEV_GOOS := $(shell go env GOOS)
GOPATH := $(shell go env GOPATH)
GOROOT := $(shell go env GOROOT)
VERSION := $(shell git show -s --format=%cd --date=format:%Y%m%d.%H%M%S)
COMMIT := $(shell git show -s --format=%h)
LDFLAGS_DEV := "-X 'github.com/snyk/snyk-ls/application/config.Development=true' -X 'github.com/snyk/snyk-ls/application/config.Version=v$(VERSION)-SNAPSHOT-$(COMMIT)'"

TOOLS_BIN := $(shell pwd)/.bin

OVERRIDE_GOCI_LINT_V := v2.10.1
GOLICENSES_V := v1.6.0
PACT_V := 2.4.2

TIMEOUT := "-timeout=90m"


## tools: Install required tooling.
.PHONY: tools
tools: $(TOOLS_BIN)/go-licenses $(TOOLS_BIN)/golangci-lint $(TOOLS_BIN)/pact/bin/pact

.PHONY: hooks
hooks:
	@pre-commit install
	@pre-commit install --hook-type pre-push


$(TOOLS_BIN)/go-licenses:
	@echo "==> Installing go-licenses"
	@GOBIN=$(TOOLS_BIN) go install github.com/google/go-licenses@$(GOLICENSES_V)

$(TOOLS_BIN)/golangci-lint:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(OVERRIDE_GOCI_LINT_V)/install.sh | sh -s -- -b $(TOOLS_BIN)/ $(OVERRIDE_GOCI_LINT_V)

$(TOOLS_BIN)/pact/bin/pact:
	cd $(TOOLS_BIN); curl -fsSL https://raw.githubusercontent.com/pact-foundation/pact-ruby-standalone/v$(PACT_V)/install.sh | PACT_CLI_VERSION=v$(PACT_V) bash

## clean: Delete the build directory
.PHONY: clean
clean:
	@echo "==> Removing '$(BUILD_DIR)' directory..."
	@rm -rf $(BUILD_DIR)

## lint: Lint code with golangci-lint.
.PHONY: lint
lint: $(TOOLS_BIN)/golangci-lint
	@echo "==> Linting code with 'golangci-lint'..."
	@$(TOOLS_BIN)/golangci-lint run ./...

## lint: Lint code with golangci-lint.
.PHONY: lint-fix
lint-fix: $(TOOLS_BIN)/golangci-lint
	@echo "==> Linting and fixing code with 'golangci-lint'..."
	@go fmt ./...
	@$(TOOLS_BIN)/golangci-lint run --fix ./...

.PHONY: format
format: lint-fix
	@echo "==> Formatting code..."

## test: Run all tests (uses Go test cache; no coverage profile by default).
## Set INTEG_TESTS=1 or SMOKE_TESTS=1 to include integration/smoke tests.
## Records which test stage passed at the current HEAD in .tests-hash.
.PHONY: test
test: test-js
	@echo "==> Running tests..."
	@mkdir -p $(BUILD_DIR)
	go test $(TIMEOUT) -failfast ./...
	@stages="test"; \
	 [ -n "$(INTEG_TESTS)" ] && stages="$$stages test-integ" || true; \
	 [ -n "$(SMOKE_TESTS)" ] && stages="$$stages test-smoke" || true; \
	 for s in $$stages; do $(MAKE) --no-print-directory _save-test-hash STAGE=$$s; done

## test-integ: Run integration tests (alias for INTEG_TESTS=1 make test).
.PHONY: test-integ
test-integ:
	INTEG_TESTS=1 $(MAKE) test

## test-smoke: Run smoke tests (alias for SMOKE_TESTS=1 make test).
.PHONY: test-smoke
test-smoke:
	SMOKE_TESTS=1 $(MAKE) test

## test-all: Run all tests
.PHONY: test-all
test-all:
	INTEG_TESTS=1 SMOKE_TESTS=1 $(MAKE) test

## test-coverage: Run unit tests with coverage profile (disables Go test cache).
.PHONY: test-coverage
test-coverage: test-js
	@echo "==> Running unit tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	go test $(TIMEOUT) -failfast -cover -coverprofile=$(BUILD_DIR)/coverage.out ./...

## check-tests: Verify all required test stages have run at the current HEAD.
.PHONY: check-tests
check-tests:
	@./scripts/check-tests-run.sh

# Internal: _update-test-hash is intentionally undocumented to prevent bypass.
# Only CI bootstrap should call it directly. Use make test/test-all
.PHONY: _update-test-hash
_update-test-hash:
	@if [ -z "$(TARGET)" ]; then \
		echo "ERROR: TARGET is required"; \
		exit 1; \
	fi
	$(MAKE) --no-print-directory _save-test-hash STAGE=$(TARGET)

.PHONY: _save-test-hash
_save-test-hash:
	@hash=$$(git rev-parse HEAD); \
	 if [ -f .tests-hash ]; then \
	     grep -v "^$(STAGE)=" .tests-hash > .tests-hash.tmp 2>/dev/null || true; \
	     mv .tests-hash.tmp .tests-hash; \
	 fi; \
	 echo "$(STAGE)=$$hash" >> .tests-hash
	@echo "✅ Stage '$(STAGE)' recorded for commit $$(git rev-parse --short HEAD)"

## benchmark: Run Go benchmarks under benchmark/ and tee results to build/benchmark-results.txt
.PHONY: benchmark
benchmark:
	@mkdir -p $(BUILD_DIR)
	go test -bench=. -benchmem -benchtime=1s -timeout=30m ./benchmark/... 2>&1 | tee $(BUILD_DIR)/benchmark-results.txt

## benchmark-real: real LS + Snyk Code + OSS scan against generated full 500+500 monorepo (requires SNYK_TOKEN; does not run in default make test).
## Optional: BENCHMARK_REAL_SCAN_PROFILE_DIR=<dir> for runtime/pprof (CPU + heap before/after scan phase); see benchmark/README.md.
.PHONY: benchmark-real
benchmark-real:
	SMOKE_TESTS=1 BENCHMARK_REAL_SCAN_MONOREPO=1 BENCHMARK_REALSCAN_FULL_FIXTURE=1 go test $(TIMEOUT) -count=1 ./application/server/... -run Test_SmokeRealScanMonorepoFixture

## test-js: Run all JavaScript tests (tree view + config dialog) and check ES5 compatibility.
.PHONY: test-js
test-js: tree-view-fixture config-dialog-fixture
	@echo "==> Running JS tests..."
	@cd js-tests && npm install --ignore-scripts && npm test
	@echo "==> Linting JS for ES5 compatibility..."
	@cd js-tests && npm run lint:es5

.PHONY: race-test
race-test:
	@echo "==> Running integration tests with race-detector..."
	@mkdir -p $(BUILD_DIR)
	INTEG_TESTS=1 SMOKE_TESTS=1 go test $(TIMEOUT) -race -failfast ./...

.PHONY: proxy-test
proxy-test:
	@echo "==> Running integration tests with proxy"
	@docker build -t "snyk-ls:$(VERSION)" -f .github/docker-based-tests/Dockerfile .
	@docker run --rm --cap-add=NET_ADMIN --name "snyk-ls" --env "SNYK_TOKEN=$(SNYK_TOKEN)" snyk-ls:$(VERSION) make instance-test

instance-test:
	@echo "==> Running instance tests"
	export SMOKE_TESTS=1 && cd application/server && go test $(TIMEOUT) -failfast -run Test_SmokeInstanceTest && cd -
	@curl -sSL https://static.snyk.io/eclipse/stable/p2.index

## tree-view-fixture: Regenerate tree view HTML fixture used by JS tests.
.PHONY: tree-view-fixture
tree-view-fixture:
	@echo "==> Generating tree view HTML fixture..."
	@mkdir -p js-tests/fixtures
	@go run scripts/tree-view/main.go > js-tests/fixtures/tree-view.html
	@echo "    Written to js-tests/fixtures/tree-view.html"

## config-dialog-fixture: Regenerate config dialog HTML fixture used by JS tests.
.PHONY: config-dialog-fixture
config-dialog-fixture:
	@echo "==> Generating config dialog HTML fixture..."
	@mkdir -p js-tests/fixtures
	@go run scripts/config-dialog/main.go --dummy-data -no-panel > js-tests/fixtures/config-page.html
	@echo "    Written to js-tests/fixtures/config-page.html"

## generate: Regenerate generated files (e.g. mocks).
.PHONY: generate
generate:
	@echo "==> Generating generated files..."
	@go generate ./...

## verify-generate: Run generate and fail if output differs from the index or generate adds new untracked files.
## Uses unstaged diff (not porcelain): staged paths alone must not fail pre-commit when generate is clean.
## Untracked check compares before/after generate so unrelated local files do not fail the hook.
.PHONY: verify-generate
verify-generate:
	@set -e; \
	UNTRACKED_BEFORE=$$(mktemp); \
	UNTRACKED_AFTER=$$(mktemp); \
	trap 'rm -f "$$UNTRACKED_BEFORE" "$$UNTRACKED_AFTER"' EXIT; \
	git ls-files --others --exclude-standard | LC_ALL=C sort > "$$UNTRACKED_BEFORE"; \
	$(MAKE) generate; \
	if ! git diff --quiet; then \
		echo "ERROR: Generated output differs from the index after \`make generate\` (unstaged changes). Review the diff, stage updates if intended, or revert."; \
		git diff; \
		exit 1; \
	fi; \
	git ls-files --others --exclude-standard | LC_ALL=C sort > "$$UNTRACKED_AFTER"; \
	NEW_UNTRACKED=$$(comm -13 "$$UNTRACKED_BEFORE" "$$UNTRACKED_AFTER"); \
	if [ -n "$$NEW_UNTRACKED" ]; then \
		echo "ERROR: New untracked paths appeared after \`make generate\`. Add them if intended, or fix generation."; \
		echo "$$NEW_UNTRACKED"; \
		exit 1; \
	fi

## build: Build binary for default local system's OS and architecture.
.PHONY: build
build:
	@echo "==> Building binary..."
	@echo "    running go build for GOOS=$(DEV_GOOS) GOARCH=$(DEV_GOARCH)"
# workaround for missing .exe extension on Windows
ifeq ($(OS),Windows_NT)
	@go build -o $(BUILD_DIR)/$(PROJECT_NAME).$(DEV_GOOS).$(DEV_GOARCH).exe \
		-ldflags=$(LDFLAGS_DEV)
else
	@go build -o $(BUILD_DIR)/$(PROJECT_NAME).$(DEV_GOOS).$(DEV_GOARCH) \
		-ldflags=$(LDFLAGS_DEV)
endif

## build-debug: Build binary for debugging
.PHONY: build-debug
build-debug:
	@make clean
	@echo "==> Building binary..."
	@echo "    running go build with debug flags"

ifeq ($(OS),Windows_NT)
	@go build -o $(BUILD_DIR)/$(PROJECT_NAME).exe \
		-ldflags=$(LDFLAGS_DEV) \
		-gcflags="all=-N -l"
else
	@go build -o $(BUILD_DIR)/$(PROJECT_NAME) \
		-ldflags=$(LDFLAGS_DEV)
		-gcflags="all=-N -l"
endif

.PHONY: build-release
build-release: $(TOOLS_BIN)/go-licenses
	@LICENSES=$(make licenses) goreleaser release --clean --snapshot

## run: Compile and run LSP server.
.PHONY: run
run:
	@echo "==> Running Snyk LS server..."
	@go run main.go --reportErrors

.PHONY: install
install:
	@echo "==> Installing binary..."
	@go install -ldflags=$(LDFLAGS_DEV)

.PHONY: license-update
license-update: $(TOOLS_BIN)/go-licenses
	@echo "==> Updating license information..."
	@# TODO - Find a better solution to prevent the deletion of manually added license files.
	@mkdir -p 'licenses_temp/github.com/brianblakely/nodep-date-input-polyfill'
	@mv 'licenses/github.com/brianblakely/nodep-date-input-polyfill/LICENSE' 'licenses_temp/github.com/brianblakely/nodep-date-input-polyfill/LICENSE'
	@rm -rf 'licenses'
	@GOROOT=$(GOROOT) $(TOOLS_BIN)/go-licenses save . --save_path="licenses" --ignore "github.com/snyk/snyk-ls"
	@mkdir -p 'licenses/github.com/brianblakely/nodep-date-input-polyfill'
	@mv 'licenses_temp/github.com/brianblakely/nodep-date-input-polyfill/LICENSE' 'licenses/github.com/brianblakely/nodep-date-input-polyfill/LICENSE'
	@rm -rf 'licenses_temp'

.PHONY: licenses
licenses: $(TOOLS_BIN)/go-licenses
	@GOROOT=$(GOROOT) $(TOOLS_BIN)/go-licenses report . --ignore github.com/snyk/snyk-ls

help: Makefile
	@echo "Usage: make <command>"
	@echo ""
	@echo "Commands:"
	@sed -n 's/^##//p' $< | column -t -s ':' | sed -e 's/^/ /'
