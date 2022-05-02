# Snyk Language Server (Snyk-LS)

[![Build Go binaries](https://github.com/snyk/snyk-ls/actions/workflows/build.yaml/badge.svg)](https://github.com/snyk/snyk-ls/actions/workflows/build.yaml)
[![Release Go binaries](https://github.com/snyk/snyk-ls/actions/workflows/release.yaml/badge.svg)](https://github.com/snyk/snyk-ls/actions/workflows/release.yaml)

## Supported features

The language server follows
the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/specifications/specification-current/)
and integrates with Snyk Open Source, Snyk Infrastructure as Code and Snyk Code. For the former two, it uses the Snyk
CLI as a data provider, for the latter it is connecting directly to the Snyk Code API.

Right now the language server supports the following actions:

- Send diagnostics to client on opening a document.
- Starting a project/folder scan on opening a project and sending diagnostics
- Cache diagnostics until Saving.
- Invalidate caches on saving a document and retrieve saved document diagnostics anew.
- Provides range calculation to correctly highlight Snyk Open Source issues in their file.
- Provides formatted hovers with diagnostic details and follow-up links
- Progress reporting to the client for background jobs
- Notifications to the client
- Authentication when needed, using the Snyk CLI and opening a webpage if necessary
- Automatic download of the Snyk CLI if none is found or configured to XDG_DATA_HOME
- Selective activation of products according to settings transmitted

### Implemented operations

### Language Server Protocol support

#### Requests

- "initialize"
- "textDocument/didOpen"
- "textDocument/didChange"
- "textDocument/didClose"
- "textDocument/didSave"
- "textDocument/hover"
- "textDocument/willSave"
- "textDocument/willSaveWaitUntil"
- "shutdown"
- "exit"
- "workspace/didChangeWorkspaceFolders"
- "workspace/didChangeConfiguration"
- window/workDoneProgress/create (from server -> client)

#### Notifications

- window/showMessage
- $/progress
- textDocument/publishDiagnostics

```go
ServerCapabilities{
  TextDocumentSync: &sglsp.TextDocumentSyncOptionsOrKind{
    Options: &sglsp.TextDocumentSyncOptions{
      OpenClose:         true,
      WillSave:          true,
      WillSaveWaitUntil: true,
      Save:              SaveOptions{IncludeText: false},
    },
  },
  WorkspaceFoldersServerCapabilities: WorkspaceFoldersServerCapabilities{
	  Supported:           true,
    ChangeNotifications: "snyk-ls",
  },
  HoverProvider: true,
}
```

### Custom additions to Language Server Protocol

- Authentication Notification
  - method: `$/hasAuthenticated`
  - payload: `HasAuthenticatedParam`
  ```go
  type AuthenticationParams struct {
    // The Snyk Token retrieved from authentication
    Token string `json:"token"`
  }
  ```

## Installation

### Download

The release workflow stores the generated executables, so that they can be
downloaded [here](https://github.com/snyk/snyk-ls/releases/tag/latest). Just select the release you want the build
artefacts from and download the zip file attached to it. Currently, executables for Windows, macOS and Linux are
generated.

### From Source

- Install `go 1.17.5` or higher, set the `GOPATH` and `GOROOT`
- Enter the root directory of this repository
- Execute `go get ./...` to download all dependencies
- Execute `go install` to produce a `snyk-ls` binary

## Configuration

### Snyk LSP Command Line Flags

`-c <FILE>` allows to specify a config file to load before all others

`-l <LOGLEVEL>` <allows to specify the log level (`trace`, `debug`, `info`, `warn`, `error`, `fatal`). The default log
level is `info`

`-o <FORMAT>` allows to specify the output format (`md` or `html`) for issues

`-f <FILE>` allows you to specify a log file instead of logging to the console

### Configuration

#### Environment variables

Snyk LS and Snyk CLI support and need certain environment variables to function:

1. `ACTIVATE_SNYK_OPEN_SOURCE` `true|false` to toggle Snyk Open Source scans
2. `ACTIVATE_SNYK_CODE` `true|false` to toggle Snyk Open Source scans
3. `ACTIVATE_SNYK_IAC` `true|false` to toggle Snyk Open Source scans
4. `DEEPROXY_API_URL` to find the Snyk Code backend service (default is `https://deeproxy.snyk.io`)
5. `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` to define the http proxy to be used
6. `JAVA_HOME` to analyse Java JVM-based projects via Snyk CLI
7. `PATH` to find the Snyk CLI, to find maven when analysing Maven projects, to find python, etc
8. `SNYK_API` to define the endpoint address if using single tenant setup
9. `SNYK_CLI_PATH` to specify where the Snyk CLI is located and to prevent automatic downloads
10. `SNYK_TOKEN` to authenticate against the Snyk backend services (alternatively, the CLI has a token storage after
    authenticating with it)

#### Auto-Configuration

To automatically add these variables to the environment, Snyk LS searches for the following files, with the order
determining precedence. If the executable is not called from an already configured environment (e.g. via
`zsh -i -c 'snyk-ls'`), you can also specify config file with the `-c` command line flag for setting the above mentioned
variables. Snyk LS reads the following files in the given precedence and order, not overwriting the already loaded
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

#### Snyk CLI

To find the Snyk CLI,
the [XDG Data Home](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html#variables)
and `PATH` path are automatically scanned for the OS-dependent file, e.g. `snyk-macos` on macOS,
`snyk-linux` on Linux and `snyk-win.exe` on Windows, and the first path where it is found is added to the environment.
It is later used for all functionality that depends on the CLI.

If the CLI `SNYK_CLI_PATH` is not set, and no CLI is found, Snyk LS starts
a [download](https://static.snyk.io/cli/latest)
of the CLI and installs it into the `XDG_DATA_HOME/snyk-ls` folder. During the download, a
lockfile `snyk-cli-download.lock` is created in the same directory which may need to be removed if the download is
interrupted and retried within one hour. After one hour, the lockfile is ignored.

#### Setting environment variables globally

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

#### Authentication to Snyk

When Snyk Language Server starts, it checks if it can find a token in the environment variable `SNYK_TOKEN`. If this is
not the case, it tries to retrieve and authenticate using the Snyk CLI. If the CLI is not authenticated either, it opens
a browser window to authenticate. After successfull authentication in the web browser, the Snyk Language Server
automatically retrieves the Snyk authentication token from the CLI.

## Run Tests

```bash
go test ./...
```

The output should look like this (it is running against the Snyk Code API and using the real CLI):

```
?       github.com/snyk/snyk-ls        [no test files]
ok      github.com/snyk/snyk-ls/code   24.201s
ok      github.com/snyk/snyk-ls/diagnostics    26.590s
ok      github.com/snyk/snyk-ls/iac    25.780s
?       github.com/snyk/snyk-ls/lsp    [no test files]
ok      github.com/snyk/snyk-ls/oss    22.427s
ok      github.com/snyk/snyk-ls/server 48.558s
ok      github.com/snyk/snyk-ls/util   9.562s
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
