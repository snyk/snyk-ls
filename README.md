# Snyk Language Server (Snyk-LSP)
[![Build Go binaries](https://github.com/snyk/snyk-ls/actions/workflows/build.yaml/badge.svg)](https://github.com/snyk/snyk-ls/actions/workflows/build.yaml)
[![Release Go binaries](https://github.com/snyk/snyk-ls/actions/workflows/release.yaml/badge.svg)](https://github.com/snyk/snyk-ls/actions/workflows/release.yaml)

## Supported features
The language server follows
the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/specifications/specification-current/)
and integrates with Snyk OSS, Snyk Infrastructure as Code and Snyk Code. For the former two, it uses the Snyk CLI as a
data provider, for the latter it is connecting directly to the Snyk Code API.

Right now the LSP supports the following actions:

- Send Diagnostics & CodeLenses to client on opening a document. Code Lenses only for Code & IaC.
- Cache diagnostics until Save.
- Invalidate caches on saving a document and retrieve everything anew.
- Provide range calculations for Snyk OSS (best-effort)

## Installation

### Download

The build workflow stores the generated executables, so that they can be
downloaded [here](https://github.com/snyk/snyk-lsp/releases/tag/latest). Just select the release you want the build
artefacts from and download the zip file attached to it. Currently, executables for Windows, macOS and Linux are
generated.

### From Source

- Install `go 1.17.5` or higher, set the `GOPATH` and `GOROOT`
- Enter the root directory of this repository
- Execute `go get ./...` to download all dependencies
- Execute `go build && go install` to produce a `snyk-lsp` binary
- Download Snyk CLI at :
    - macOS: https://static.snyk.io/cli/latest/snyk-macos
    - Windows: https://static.snyk.io/cli/latest/snyk-win.exe
    - Linux: https://static.snyk.io/cli/latest/snyk-linux
- Rename it to `snyk` and move it to a directory in your path, e.g. `/usr/local/bin` or `$GOPATH/bin`

## Configuration

### Snyk LSP Command Line Flags

`-c` allows to specify a config file to load before all others

`-l` allows to specify the log level (`trace`, `debug`, `info`, `warn`, `error`, `fatal`). The default log level
is `info`

`-o` allows to specify the output format (`md` or `html`) for issues

### Auto-Configuration

Snyk LSP and Snyk CLI support and need
certain [environment variables](https://docs.snyk.io/features/snyk-cli/commands/code#https_proxy-and-http_proxy) to
function:

1. `JAVA_HOME` to analyse Java JVM-based projects via Snyk CLI
2. `PATH` to find the Snyk CLI, to find maven when analysing Maven projects, to find python, etc
3. `SNYK_TOKEN` to authenticate against the Snyk backend services
4. `DEEPROXY_API_URL` to find the Snyk Code backend service (default is `https://deeproxy.snyk.io`)
5. `SNYK_API` to define the endpoint address if using single tenant setup
6. `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` to define the http proxy to be used

To automatically add these variables to the environment, Snyk LSP searches for the following files, with the order
determining precedence. If the executable is not called from an already configured environment (e.g. via
`zsh -i -c 'snyk-lsp'`), you can specify a config file with the `-c` command line flag for setting the above mentioned
variables. Snyk LSP reads the following files in the given precedence and order, not overwriting the already loaded
variables.

```bash
given config file via -c flag
<working-dir>/.snyk.env
$HOME/.snyk.env
$HOME/.zshrc.local
$HOME/.zshrc
$HOME/.bashrc
$HOME/.profile
/etc/launchd.conf
/etc/profile
/etc/environment
```

Any lines that contain an environment variable in the format
`VARIABLENAME=VARIABLEVALUE` are added automatically to the environment if not already existent. This adheres to the
`dotenv` format. In case of `.profile`, `.zshrc`, etc., if a variable is directly exported e.g. via
`export VARIABLENAME=VARIABLEVALUE`, it is not loaded. The export would need to be split of and be in its own line, e.g

```bash
VARIABLENAME=VARIABLEVALUE
export VARIABLENAME
```

The PATH variable is treated differently than all other variables, as it is an aggregate of all PATH variables found in
the files and in the environment. Also, the current working directory `.` is automatically added to the path, so a
download of the Snyk CLI into the current working directory by an LSP client would yield a found Snyk CLI for the
Language Server.

To find the Snyk CLI, the path is automatically searched for a file named `snyk` resp. `snyk.exe` on Windows, and the
first path where it is found is added to the environment. It is later used for all functionality that depends on the
CLI.

If you want to have the environment variables available system wide, you would need to add the variables
to `/etc/environment` or on macOS to `/etc/launchd.conf` or set them via `launchctl` in a shell script. The former two
locations are automatically read by snyk lsp. On Windows, a user variable can be defined via the UI for the user or
system-wide. In a file like `~/.profile` it would like this:

```bash
SNYK_TOKEN=<your-token-from-app.snyk.io>
DEEPROXY_API_URL=https://deeproxy.snyk.io/

# export variables, but make sure the export is not on the same line as the variable definition
export SNYK_TOKEN
export DEEPROXY_API_URL
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
- util              miscellaneous utilities & overall configuration
```

## Run Tests

```bash
go test ./...
```

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
