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
VERSION := $(shell git show -s --format=%cd --date=format:%Y%m%d.%H%M%S)
COMMIT := $(shell git show -s --format=%h)
LDFLAGS_DEV := "-X 'github.com/snyk/snyk-ls/application/config.Development=true' -X 'github.com/snyk/snyk-ls/application/config.Version=v$(VERSION)-SNAPSHOT-$(COMMIT)'"

NOCACHE := "-count=1"
TIMEOUT := "-timeout=45m"


# NOTE: Until this PR is merged https://github.com/pact-foundation/pact-ruby-standalone/pull/89 we need to duplicate the install script
# curl -fsSL https://raw.githubusercontent.com/pact-foundation/pact-ruby-standalone/master/install.sh | bash;\
# TODO: clean up this script once the PR is merged

## tools: Install required tooling.
.PHONY: tools
tools:
	@echo "==> Installing go-licenses"
	@go install github.com/google/go-licenses@latest
ifeq (,$(wildcard ./.bin/golangci-lint*))
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b .bin/ v1.54.2
else
	@echo "==> golangci-lint is already installed"
endif
	@./install-pact.py
	@echo "Please make sure to install NPM locally to be able to run analytics verification Ampli."

## clean: Delete the build directory
.PHONY: clean
clean:
	@echo "==> Removing '$(BUILD_DIR)' directory..."
	@rm -rf $(BUILD_DIR)

## lint: Lint code with golangci-lint.
.PHONY: lint
lint: tools
	@echo "==> Linting code with 'golangci-lint'..."
	@.bin/golangci-lint run ./...

## test: Run all tests.
.PHONY: test
test:
	@echo "==> Running unit tests..."
	@mkdir -p $(BUILD_DIR)
	@go test $(NOCACHE) $(TIMEOUT) -failfast -cover -coverprofile=$(BUILD_DIR)/coverage.out ./...

.PHONY: race-test
race-test:
	@echo "==> Running integration tests with race-detector..."
	@mkdir -p $(BUILD_DIR)
	@export INTEG_TESTS=true
	@go test $(NOCACHE) $(TIMEOUT) -race -failfast ./...

.PHONY: proxy-test
proxy-test:
	@echo "==> Running integration tests with proxy"
	@docker build -t "snyk-ls:$(VERSION)" -f .github/docker-based-tests/Dockerfile .
	@docker run --rm --cap-add=NET_ADMIN --name "snyk-ls" --env "SNYK_TOKEN=$(SNYK_TOKEN)" snyk-ls:$(VERSION) go test -failfast $(NOCACHE) $(TIMEOUT) ./...

instance-test:
	@echo "==> Running instance tests with proxy"
	@export SMOKE_TESTS=1 && cd application/server && go test -run Test_SmokeWorkspaceScanOssAndCode && cd -

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
license-update:
	@echo "==> Updating license information..."
	@rm -rf licenses
	@go-licenses save . --save_path="licenses" --ignore "github.com/snyk/snyk-ls"

# Verifies event tracking implementation in source code
verify-analytics:
ifeq ($(AMPLITUDE_KEY),)
	@npx --yes @amplitude/ampli status -u --skip-update-on-default-branch
else
	@npx --yes @amplitude/ampli status -u --skip-update-on-default-branch -t $(AMPLITUDE_KEY)
endif

help: Makefile
	@echo "Usage: make <command>"
	@echo ""
	@echo "Commands:"
	@sed -n 's/^##//p' $< | column -t -s ':' | sed -e 's/^/ /'
