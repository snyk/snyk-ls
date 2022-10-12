# Snyk Language Server (Snyk-LS)

[![Build Go binaries](https://github.com/snyk/snyk-ls/actions/workflows/build.yaml/badge.svg)](https://github.com/snyk/snyk-ls/actions/workflows/build.yaml)
[![Release Go binaries](https://github.com/snyk/snyk-ls/actions/workflows/release.yaml/badge.svg)](https://github.com/snyk/snyk-ls/actions/workflows/release.yaml)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

## Supported features

The language server follows
the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/specifications/specification-current/)
and integrates with Snyk Open Source, Snyk Infrastructure as Code and Snyk Code. For the former two, it uses the Snyk
CLI as a data provider, for the latter it is connecting directly to the Snyk Code API.

Right now the language server supports the following actions:

- Send diagnostics to client on opening a document if it's part of the current set of folders.
- Starting a folder scan on startup and sending diagnostics.
- Starting a workspace scan of all folders on command.
- Cache diagnostics until saving or triggering a new workspace scan.
- Invalidate caches on saving a document and retrieve saved document diagnostics anew.
- Provides range calculation to correctly highlight Snyk Open Source issues in their file.
- Provides formatted hovers with diagnostic details and follow-up links
- Progress reporting to the client for background jobs
- Notifications to the client
- Authentication when needed, using the Snyk CLI and opening a webpage if necessary
- Copying the authentication URL to clipboard if there are problems opening a webpage
- Automatic download of the Snyk CLI if none is found or configured to XDG_DATA_HOME
- Selective activation of products according to settings transmitted

### Implemented operations

### Language Server Protocol support

#### Requests

- initialize
- exit
- textDocument/codeAction
- textDocument/codeLens
- textDocument/didOpen
- textDocument/didClose
- textDocument/didSave
- textDocument/hover
- shutdown
- workspace/didChangeWorkspaceFolders
- workspace/didChangeConfiguration
- workspace/executeCommand
- window/workDoneProgress/create (from server -> client)
- window/showMessage
- window/showDocument

#### Notifications

- window/showMessage
- $/progress
- textDocument/publishDiagnostics

### Custom additions to Language Server Protocol

- Authentication Notification
  - method: `$/snyk.hasAuthenticated`
  - payload:
  ```json
  {
    "token": "the snyk token"
  }
  ```

- Cli Path Notification
  - method: `$/snyk.isAvailableCli`
  - payload:
  ```json
  {
    "cliPath": "/a/path/to/cli-executable"
  }
  ```

## Installation

### Download

The release workflow stores the generated executables, so that they can be
downloaded [here](https://github.com/snyk/snyk-ls/releases/tag/latest). Just select the release you want the build
artefacts from and download the zip file attached to it. Currently, executables for Windows, macOS and Linux are
generated.

The currently published binary can be retrieved with [this](getLanguageServer.sh) bash script, please keep in mind that
[the protocol version](.goreleaser.yaml) is part of the download link and can change to force plugin / language server
synchronization. For further information please see [CONTRIBUTING.md](CONTRIBUTING.md).

### From Source

- Install `go 1.18` or higher, set the `GOPATH` and `GOROOT`
- Enter the root directory of this repository
- Execute `go get ./...` to download all dependencies
- Execute `make build && make install` to produce a `snyk-ls` binary

## Configuration

### Snyk LSP Command Line Flags

`-c <FILE>` allows to specify a config file to load before all others

`-l <LOGLEVEL>` <allows to specify the log level (`trace`, `debug`, `info`, `warn`, `error`, `fatal`). The default log
level is `info`

`-o <FORMAT>` allows to specify the output format (`md` or `html`) for issues

`-f <FILE>` allows you to specify a log file instead of logging to the console

`-licenses` displays the [licenses](https://github.com/snyk/snyk-ls/tree/main/licenses) used by Language Server

### Configuration

#### LSP Initialization Options

As part of
the [Initialize message](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#initialize)
within `initializationOptions?: LSPAny;` we support the following settings:

```json5
{
  "activateSnykOpenSource": "true", // Enables Snyk Open Source - defaults to true
  "activateSnykCode": "false", // Enables Snyk Code, if enabled for your organization - defaults to false
  "activateSnykIac":  "true", // Enables Infrastructure as Code - defaults to true
  "insecure": "false", // Allows custom CAs (Certification Authorities)
  "endpoint":  "https://example.com", // Snyk API Endpoint required for non-default multi-tenant and single-tenant setups
  "additionalParams": "--all-projects", // Any extra params for the Snyk CLI, separated by spaces
  "additionalEnv":  "MAVEN_OPTS=-Djava.awt.headless=true;FOO=BAR", // Additional environment variables, separated by semicolons
  "path": "/usr/local/bin", // Adds to the system path used by the CLI
  "sendErrorReports":  "true", // Whether or not to report errors to Snyk - defaults to true
  "organization": "a string", // The name of your organization, e.g. the output of: curl -H "Authorization: token $(snyk config get api)"  https://snyk.io/api/cli-config/settings/sast | jq .org
  "enableTelemetry":  "true", // Whether or not user analytics can be tracked
  "manageBinariesAutomatically": "true", // Whether or not CLI/LS binaries will be downloaded & updated automatically
  "cliPath":  "/a/patch/snyk-cli" // The path where the CLI can be found, or where it should be downloaded to
  "token":  "secret-token" // The Snyk token, e.g.: snyk config get api
  "automaticAuthentication": "true" // Whether or not LS will automatically authenticate on scan start (default: true)
}
```

#### Environment variables

Snyk LS and Snyk CLI support and need certain environment variables to function:

1. `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` to define the http proxy to be used
1. `JAVA_HOME` to analyse Java JVM-based projects via Snyk CLI
1. `PATH` to find maven when analysing Maven projects, to find python, etc

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

In addition to configuring variables via config files, Snyk LS adds the following directories to the path on linux
and macOS:

- /bin
- $HOME/bin
- /usr/local/bin
- $JAVA_HOME/bin

If no JAVA_HOME is set, it automatically searches for a java executable first in path, then in the following directories
and adds the parent directory of its parent as JAVA_HOME. The following directories are recursively searched:

- /usr/lib
- /usr/java
- /opt
- /Library
- $HOME/.sdkman
- C:\Program Files
- C:\Program Files (x86)

The same directories are searched for a maven executable and the parent directory is added to the path.

#### Snyk CLI

To find the automatically managed Snyk CLI,
the [XDG Data Home](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html#variables)
and `PATH` path are automatically scanned for the OS-dependent file, e.g. `snyk-macos` on macOS,
`snyk-linux` on Linux and `snyk-win.exe` on Windows, and the first path where it is found is added to the environment.
It is later used for all functionality that depends on the CLI.

#### Setting environment variables globally

If you want to have the environment variables available system-wide, you would need to add the variables
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

The Snyk LS authentication flow is as follows. When Snyk Language Server starts, it:
- Checks if it can find a token in the environment variable `SNYK_TOKEN`
- If this is not the set, it tries to retrieve and authenticate using the Snyk CLI
- If the CLI is not authenticated either, it opens a browser window to authenticate
- If there are problems opening the browser window, the auth URL can be copied to the clipboard (via implementation of `snyk.copyAuthLink`). _Note that there is a requirement to have `xsel` or `xclip` installed for Linux/Unix users for this feature._

After successfull authentication in the web browser, the Snyk Language Server
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
