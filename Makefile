# project variables
PROJECT_NAME := snyk-ls

# build variables
.DEFAULT_GOAL = test
BUILD_DIR := build
DEV_GOARCH := $(shell go env GOARCH)
DEV_GOOS := $(shell go env GOOS)
GOPATH := $(shell go env GOPATH)
VERSION := $(shell git show -s --format=%cd --date=format:%Y%m%d.%H%M%S)
COMMIT := $(shell git show -s --oneline)
LDFLAGS_DEV := "-X 'github.com/snyk/snyk-ls/config.Development=true' -X 'github.com/snyk/snyk-ls/config.Version=v$(VERSION)-SNAPSHOT-$(COMMIT)'"

## tools: Install required tooling.
.PHONY: tools
tools:
ifeq (,$(wildcard ./.bin/golangci-lint*))
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b .bin/ v1.45.2
else
	@echo "==> Required tooling is already installed"
endif

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

## test: Run all unit tests.
.PHONY: test
test:
	@echo "==> Running unit tests..."
	@mkdir -p $(BUILD_DIR)
	@go test -count=1 -v -cover -coverprofile=$(BUILD_DIR)/coverage.out -p=1 -timeout=300s ./...

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

## run: Compile and run LSP server.
.PHONY: run
run:
	@echo "==> Running Snyk LS server..."
	@go run main.go --reportErrors

.PHONY: install
install:
	@echo "==> Installing binary..."
	@go install -ldflags=$(LDFLAGS_DEV)

help: Makefile
	@echo "Usage: make <command>"
	@echo ""
	@echo "Commands:"
	@sed -n 's/^##//p' $< | column -t -s ':' | sed -e 's/^/ /'
