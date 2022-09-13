# project variables
PROJECT_NAME := snyk-ls

# build variables
.DEFAULT_GOAL = test
BUILD_DIR := build
DEV_GOARCH := $(shell go env GOARCH)
DEV_GOOS := $(shell go env GOOS)
GOPATH := $(shell go env GOPATH)
VERSION := $(shell git show -s --format=%cd --date=format:%Y%m%d.%H%M%S)
LICENSES := $(shell go-licenses report . --ignore github.com/snyk/snyk-ls)
COMMIT := $(shell git show -s --format=%h)
LDFLAGS_DEV := "-X 'github.com/snyk/snyk-ls/application/config.Development=true' -X 'github.com/snyk/snyk-ls/application/config.LicenseInformation=$(LICENSES)' -X 'github.com/snyk/snyk-ls/application/config.Version=v$(VERSION)-SNAPSHOT-$(COMMIT)'"

PARALLEL := "-p=1"
NOCACHE := "-count=1"
VERBOSE := "-v"
TIMEOUT := "-timeout=15m"

## tools: Install required tooling.
.PHONY: tools
tools:
	@echo "==> Installing go-licenses"
	@go install github.com/google/go-licenses@latest
ifeq (,$(wildcard ./.bin/golangci-lint*))
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b .bin/ v1.48.0
else
	@echo "==> golangci-lint is already installed"
endif
	@if [ ! -d ./.bin/pact ]; then\
		echo "--- 🛠 Installing Pact CLI dependencies";\
		curl -fsSL https://raw.githubusercontent.com/pact-foundation/pact-ruby-standalone/master/install.sh | bash;\
		mkdir ./.bin/pact;\
		mv ./pact/* ./.bin/pact;\
		export PATH=$PATH:$PWD/.bin/pact;\
	else \
		echo "==> Pact CLI is already installed";\
	fi

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
	@go test $(PARALLEL) $(NOCACHE) $(TIMEOUT) $(VERBOSE) -failfast -cover -coverprofile=$(BUILD_DIR)/coverage.out ./...

.PHONY: race-test
race-test:
	@echo "==> Running integration tests with race-detector..."
	@mkdir -p $(BUILD_DIR)
	@export INTEG_TESTS=true
	@go test $(PARALLEL) $(NOCACHE) $(TIMEOUT) $(VERBOSE) -race -failfast ./...

.PHONY: proxy-test
proxy-test:
	@echo "==> Running integration tests with proxy"
	@docker build -t "snyk-ls:$(VERSION)" -f .github/docker-based-tests/Dockerfile .
	@docker run --rm --cap-add=NET_ADMIN --name "snyk-ls" --env "SNYK_TOKEN=$(SNYK_TOKEN)" snyk-ls:$(VERSION) go test -failfast $(PARALLEL) $(NOCACHE) $(TIMEOUT) $(VERBOSE) ./...


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
	@go build -o $(BUILD_DIR)/$(PROJECT_NAME) \
		-ldflags=$(LDFLAGS_DEV) \
		-gcflags="all=-N -l"

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

help: Makefile
	@echo "Usage: make <command>"
	@echo ""
	@echo "Commands:"
	@sed -n 's/^##//p' $< | column -t -s ':' | sed -e 's/^/ /'
