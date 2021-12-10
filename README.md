# Snyk Language Server (Snyk-LSP)
[![Build Go binaries](https://github.com/snyk/snyk-lsp/actions/workflows/workflow.yaml/badge.svg)](https://github.com/snyk/snyk-lsp/actions/workflows/workflow.yaml)

## Supported features
The language server integrates with Snyk OSS, Snyk Infrastructure as Code and Snyk Code. For the former two, 
it uses the Snyk CLI as a data provider, for the latter it is connecting directly to the Snyk Code API.

Right now the LSP supports the following actions:

- Send Diagnostics & CodeLenses to client on opening a document
- Invalidate caches on saving a document and retrieve everything anew.
- Cache diagnostics until Save.
- Provide range calculations for Snyk OSS (best-effort)

## Installation

### Download
The build workflow stores the generated executables, so that they can be
downloaded [here](https://github.com/snyk/snyk-lsp/releases/tag/latest). Just select the release you want the build
artefacts from and download the zip file attached to it. Currently, executables for Windows, macOS and Linux are
generated.

### From Source

- Install `go 1.17.2` or higher, set the `GOPATH` and `GOROOT`
- enter the root directory of this repository
- execute `go get ./...` to download all dependencies
- execute `go build && go install` to produce a `snyk-lsp` binary
- download Snyk CLI at https://static.snyk.io/cli/latest/snyk-macos | snyk-win.exe | snyk-linux 
- rename it to `snyk` and move it to a directory in your path, e.g. `/usr/local/bin` or `$GOPATH/bin` 

Update your environment

```
export SNYK_TOKEN=<your-token-from-app.snyk.io>
export DEEPROXY_API_URL=https://deeproxy.snyk.io/
```
If you want to have the environment variables available system wide, you would need to 
add the above lines to `~/.profile` and set them via `launchctl` on macOs. On Windows, 
a user variable can be defined via the UI.

### macOs
```
launchctl setenv SNYK_TOKEN "<your-token-from-app.snyk.io>"
launchctl setenv DEEPROXY_API_URL "https://deeproxy.snyk.io/"
launchctl setenv PATH "$PATH"
```

## Configure your client
See [here](https://docs.google.com/document/d/1nUAt4ckza1y1PEE3p4BUsnlmQkE4ltuYURJkYeusYpA/) for details.
You will at least have to update the path to the snyk-lsp executable. 

## Code Structure
```
|
main.go             starts the server
- .github           contains CI/CD and CODEOWNERS document
- code              snyk code functionality
- diagnostics       business logic for caching and retrieving diagnostics
- iac               snyk infrastructure as code functionality
- oss               snyk oss functionality
- server            LSP / JSON-RPC 2.0 handler registration and serving
- util              miscellaneous utilities
```

## Run Tests
```go test ./...```

The output should look like this (it is running against the Snyk Code API and using the real CLI):

```
?       github.com/snyk/snyk-lsp        [no test files]
ok      github.com/snyk/snyk-lsp/code   24.201s
ok      github.com/snyk/snyk-lsp/diagnostics    26.590s
ok      github.com/snyk/snyk-lsp/iac    25.780s
?       github.com/snyk/snyk-lsp/lsp    [no test files]
ok      github.com/snyk/snyk-lsp/oss    22.427s
ok      github.com/snyk/snyk-lsp/server 48.558s
ok      github.com/snyk/snyk-lsp/util   9.562s
```

## Test Github Action locally

You can test github actions locally using [act](https://github.com/nektos/act).

### Install act & prerequisites

```bash
brew install act

# if you don't have docker desktop you can use minikube (a one-node kubernetes distribution)
brew install --cask virtualbox # you need to enable the virtualbox extension in macOS settings
brew install minikube
minikube start
eval $(minikube docker-env) # gives you a fully functional docker environment 
```

### Run act

```bash
act --secret SNYK_TOKEN=$SNYK_TOKEN --secret DEEPROXY_API_URL=$DEEPROXY_API_URL
```