# project variables
PROJECT_NAME := snyk-ls

# build variables
.DEFAULT_GOAL = test
BUILD_DIR := build
DEV_GOARCH := $(shell go env GOARCH)
DEV_GOOS := $(shell go env GOOS)
GOPATH := $(shell go env GOPATH)


## tools: Install required tooling.
.PHONY: tools
tools:
ifeq (,$(wildcard ./.bin/golangci-lint*))
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b .bin/ v1.44.2
else
	@echo "==> Required tooling is already installed"
endif

##
.PHONY: goreleaser
goreleaser:
	@echo "==> Installing goreleaser..."
	@go install github.com/goreleaser/goreleaser@latest

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
	@go test -count=1 -v -cover -coverprofile=$(BUILD_DIR)/coverage.out -parallel=4 ./...

## build: Build binary for default local system's OS and architecture.
.PHONY: build
build:
	@echo "==> Building binary..."
	@echo "    running go build for GOOS=$(DEV_GOOS) GOARCH=$(DEV_GOARCH)"
# workaround for missing .exe extension on Windows
ifeq ($(OS),Windows_NT)
	@go build -o $(BUILD_DIR)/$(PROJECT_NAME).$(DEV_GOOS).$(DEV_GOARCH).exe \
		-ldflags='-X 'github.com/snyk/snyk-ls/config.Development=true''
else
	@go build -o $(BUILD_DIR)/$(PROJECT_NAME).$(DEV_GOOS).$(DEV_GOARCH) \
		-ldflags='-X 'github.com/snyk/snyk-ls/config.Development=true''
endif

## run: Compile and run LSP server.
.PHONY: run
run:
	@echo "==> Running Snyk LS server..."
	@go run main.go --reportErrors

.PHONY: install
install:
	@echo "==> Creating Snapshot Release..."
	@goreleaser release --rm-dist --snapshot
ifneq ($(OS),Windows_NT)
	@cp -f build/snyk-ls_$(DEV_GOOS)_$(DEV_GOARCH)/* $(GOPATH)/bin
endif

help: Makefile
	@echo "Usage: make <command>"
	@echo ""
	@echo "Commands:"
	@sed -n 's/^##//p' $< | column -t -s ':' | sed -e 's/^/ /'
