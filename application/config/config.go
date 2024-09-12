/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adrg/xdg"
	"github.com/denisbrodbeck/machineid"
	"github.com/rs/zerolog"
	"github.com/subosito/gotenv"
	"github.com/xtgo/uuid"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/infrastructure/cli/filename"
	"github.com/snyk/snyk-ls/internal/concurrency"
	gitconfig "github.com/snyk/snyk-ls/internal/git_config"
	"github.com/snyk/snyk-ls/internal/logging"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	deeproxyApiUrlKey     = "DEEPROXY_API_URL"
	FormatHtml            = "html"
	FormatMd              = "md"
	snykCodeTimeoutKey    = "SNYK_CODE_TIMEOUT" // timeout as duration (number + unit), e.g. 10m
	DefaultSnykApiUrl     = "https://api.snyk.io"
	DefaultSnykUiUrl      = "https://app.snyk.io"
	DefaultDeeproxyApiUrl = "https://deeproxy.snyk.io"
	pathListSeparator     = string(os.PathListSeparator)
	windows               = "windows"
)

var (
	Version                        = "SNAPSHOT"
	LsProtocolVersion              = "development"
	Development                    = "true"
	currentConfig                  *Config
	mutex                          = &sync.Mutex{}
	LicenseInformation             = "License information\n FILLED DURING BUILD"
	analyticsPermittedEnvironments = map[string]bool{
		"api.snyk.io":    true,
		"api.us.snyk.io": true,
	}
)

type CliSettings struct {
	Insecure                bool
	AdditionalOssParameters []string
	cliPath                 string
	cliPathAccessMutex      sync.RWMutex
	C                       *Config
}

func NewCliSettings(c *Config) *CliSettings {
	c.m.Lock()
	defer c.m.Unlock()
	settings := &CliSettings{C: c}
	settings.SetPath("")
	return settings
}

func (c *CliSettings) Installed() bool {
	c.cliPathAccessMutex.RLock()
	defer c.cliPathAccessMutex.RUnlock()
	stat, err := c.CliPathFileInfo()
	isDirectory := stat != nil && stat.IsDir()
	if isDirectory {
		c.C.Logger().Warn().Msgf("CLI path (%s) refers to a directory and not a file", c.cliPath)
	}
	return c.cliPath != "" && err == nil && !isDirectory
}

func (c *CliSettings) CliPathFileInfo() (os.FileInfo, error) {
	c.cliPathAccessMutex.RLock()
	defer c.cliPathAccessMutex.RUnlock()
	stat, err := os.Stat(c.cliPath)
	if err == nil {
		c.C.Logger().Debug().Str("method", "config.cliSettings.Installed").Msgf("CLI path: %s, Size: %d, Perm: %s",
			c.cliPath,
			stat.Size(),
			stat.Mode().Perm())
	}
	return stat, err
}

func (c *CliSettings) IsPathDefined() bool {
	c.cliPathAccessMutex.RLock()
	defer c.cliPathAccessMutex.RUnlock()
	return c.cliPath != ""
}

// Path returns the full path to the CLI executable that is stored in the CLI configuration
func (c *CliSettings) Path() string {
	c.cliPathAccessMutex.RLock()
	defer c.cliPathAccessMutex.RUnlock()
	return filepath.Clean(c.cliPath)
}

func (c *CliSettings) SetPath(path string) {
	c.cliPathAccessMutex.Lock()
	defer c.cliPathAccessMutex.Unlock()
	if path == "" {
		path = filepath.Join(c.DefaultBinaryInstallPath(), filename.ExecutableName)
	}
	c.cliPath = path
}

func (c *CliSettings) DefaultBinaryInstallPath() string {
	lsPath := filepath.Join(xdg.DataHome, "snyk-ls")
	err := os.MkdirAll(lsPath, 0755)
	if err != nil {
		c.C.Logger().Err(err).Str("method", "lsPath").Msgf("couldn't create %s", lsPath)
		return ""
	}
	return lsPath
}

type Config struct {
	scrubbingDict                    frameworkLogging.ScrubbingDict
	scrubbingWriter                  zerolog.LevelWriter
	configLoaded                     concurrency.AtomicBool
	cliSettings                      *CliSettings
	configFile                       string
	format                           string
	isErrorReportingEnabled          concurrency.AtomicBool
	isSnykCodeEnabled                concurrency.AtomicBool
	isSnykOssEnabled                 concurrency.AtomicBool
	isSnykIacEnabled                 concurrency.AtomicBool
	isSnykContainerEnabled           concurrency.AtomicBool
	isSnykAdvisorEnabled             concurrency.AtomicBool
	manageBinariesAutomatically      concurrency.AtomicBool
	logPath                          string
	logFile                          *os.File
	snykCodeAnalysisTimeout          time.Duration
	snykApiUrl                       string
	snykCodeApiUrl                   string
	token                            string
	deviceId                         string
	clientCapabilities               types.ClientCapabilities
	path                             string
	defaultDirs                      []string
	automaticAuthentication          bool
	tokenChangeChannels              []chan string
	filterSeverity                   types.SeverityFilter
	trustedFolders                   []string
	trustedFoldersFeatureEnabled     bool
	activateSnykCodeSecurity         bool
	activateSnykCodeQuality          bool
	osPlatform                       string
	osArch                           string
	runtimeName                      string
	runtimeVersion                   string
	automaticScanning                bool
	authenticationMethod             types.AuthenticationMethod
	engine                           workflow.Engine
	enableSnykLearnCodeActions       bool
	enableSnykOSSQuickFixCodeActions bool
	enableDeltaFindings              bool
	logger                           *zerolog.Logger
	storage                          storage.StorageWithCallbacks
	m                                sync.RWMutex
	clientProtocolVersion            string
	isOpenBrowserActionEnabled       bool
	folderAdditionalParameters       map[string][]string
	hoverVerbosity                   int
	offline                          bool
}

func CurrentConfig() *Config {
	mutex.Lock()
	defer mutex.Unlock()
	if currentConfig == nil {
		currentConfig = New()
	}
	return currentConfig
}

func SetCurrentConfig(config *Config) {
	mutex.Lock()
	defer mutex.Unlock()
	currentConfig = config
}

func (c *Config) ClientProtocolVersion() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.clientProtocolVersion
}

func IsDevelopment() bool {
	parseBool, _ := strconv.ParseBool(Development)
	return parseBool
}

// New creates a configuration object with default values
func New() *Config {
	c := &Config{}
	c.folderAdditionalParameters = make(map[string][]string)
	c.scrubbingDict = frameworkLogging.ScrubbingDict{}
	c.logger = getNewScrubbingLogger(c)
	c.cliSettings = NewCliSettings(c)
	c.automaticAuthentication = true
	c.configFile = ""
	c.format = FormatMd
	c.isErrorReportingEnabled.Set(true)
	c.isSnykOssEnabled.Set(true)
	c.isSnykIacEnabled.Set(true)
	c.manageBinariesAutomatically.Set(true)
	c.logPath = ""
	c.snykCodeAnalysisTimeout = c.snykCodeAnalysisTimeoutFromEnv()
	c.token = ""
	c.trustedFoldersFeatureEnabled = true
	c.automaticScanning = true
	c.authenticationMethod = types.TokenAuthentication
	initWorkFlowEngine(c)
	c.deviceId = c.determineDeviceId()
	c.addDefaults()
	c.filterSeverity = types.DefaultSeverityFilter()
	c.UpdateApiEndpoints(DefaultSnykApiUrl)
	c.enableSnykLearnCodeActions = true
	c.clientSettingsFromEnv()
	c.hoverVerbosity = 3
	return c
}

func initWorkFlowEngine(c *Config) {
	c.m.Lock()
	defer c.m.Unlock()
	conf := configuration.NewInMemory()
	conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
	enableOAuth := c.authenticationMethod == types.OAuthAuthentication
	conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, enableOAuth)
	conf.Set(auth.AUTH_STYLE, oauth2.AuthStyleInParams)

	c.engine = app.CreateAppEngineWithOptions(app.WithConfiguration(conf), app.WithZeroLogger(c.logger))

	err := localworkflows.InitWhoAmIWorkflow(c.engine)
	if err != nil {
		c.Logger().Err(err).Msg("unable to initialize WhoAmI workflow")
	}

	err = c.engine.Init()
	if err != nil {
		c.Logger().Warn().Err(err).Msg("unable to initialize workflow engine")
	}

	// if running in standalone-mode, runtime info is not set, else, when in extension mode
	// it's already set by the CLI initialization
	// see https://github.com/snyk/cli/blob/main/cliv2/cmd/cliv2/main.go#L460
	if c.engine.GetRuntimeInfo() == nil {
		rti := runtimeinfo.New(runtimeinfo.WithName("snyk-ls"), runtimeinfo.WithVersion(Version))
		c.engine.SetRuntimeInfo(rti)
	}
}

func getNewScrubbingLogger(c *Config) *zerolog.Logger {
	c.m.Lock()
	defer c.m.Unlock()
	c.scrubbingWriter = frameworkLogging.NewScrubbingWriter(logging.New(nil), c.scrubbingDict)
	writer := c.getConsoleWriter(c.scrubbingWriter)
	logger := zerolog.New(writer).With().Timestamp().Str("separator", "-").Str("method", "").Str("ext", "").Logger()
	return &logger
}

func (c *Config) AddBinaryLocationsToPath(searchDirectories []string) {
	c.m.Lock()
	c.defaultDirs = searchDirectories
	c.m.Unlock()
	c.determineJavaHome()
	c.mavenDefaults()
}

func (c *Config) determineDeviceId() string {
	c.m.RLock()
	defer c.m.RUnlock()
	id, machineErr := machineid.ProtectedID("Snyk-LS")
	if machineErr != nil {
		c.Logger().Err(machineErr).Str("method", "config.New").Msg("cannot retrieve machine id")
		if c.token != "" {
			return util.Hash([]byte(c.token))
		} else {
			return uuid.NewTime().String()
		}
	} else {
		return id
	}
}

func (c *Config) IsTrustedFolderFeatureEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.trustedFoldersFeatureEnabled
}

func (c *Config) SetTrustedFolderFeatureEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.trustedFoldersFeatureEnabled = enabled
}

func (c *Config) Load() {
	c.LoadShellEnvironment()

	c.m.RLock()
	files := c.configFiles()
	c.m.RUnlock()
	for _, fileName := range files {
		c.loadFile(fileName)
	}

	c.m.Lock()
	c.configLoaded.Set(true)
	c.m.Unlock()
}

func (c *Config) LoadShellEnvironment() {
	if runtime.GOOS == "windows" {
		return
	}
	parsedEnv := getParsedEnvFromShell("bash")
	shell := parsedEnv["SHELL"]
	fromSpecificShell := getParsedEnvFromShell(shell)

	if len(fromSpecificShell) > 0 {
		c.setParsedVariablesToEnv(fromSpecificShell)
	} else {
		c.setParsedVariablesToEnv(parsedEnv)
	}
}

func getParsedEnvFromShell(shell string) gotenv.Env {
	// guard against command injection
	var shellWhiteList = map[string]bool{
		"bash":      true,
		"/bin/zsh":  true,
		"/bin/sh":   true,
		"/bin/fish": true,
		"/bin/csh":  true,
		"/bin/ksh":  true,
		"/bin/bash": true,
	}

	if !shellWhiteList[shell] {
		return gotenv.Env{}
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFunc()

	env, err := exec.CommandContext(ctx, shell, "--login", "-i", "-c", "env && exit").Output()
	if err != nil {
		return gotenv.Env{}
	}
	parsedEnv := gotenv.Parse(strings.NewReader(string(env)))
	return parsedEnv
}

func (c *Config) loadFile(fileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		c.Logger().Debug().Str("method", "loadFile").Msg("Couldn't load " + fileName)
		return
	}
	defer func(file *os.File) { _ = file.Close() }(file)
	env := gotenv.Parse(file)
	c.setParsedVariablesToEnv(env)
	c.updatePath(".")
	c.Logger().Debug().Str("fileName", fileName).Msg("loaded.")
}

func (c *Config) setParsedVariablesToEnv(env gotenv.Env) {
	for k, v := range env {
		_, exists := os.LookupEnv(k)
		if !exists {
			err := os.Setenv(k, v)
			if err != nil {
				c.Logger().Warn().Str("method", "setParsedVariablesToEnv").Msg("Couldn't set environment variable " + k)
			}
		} else {
			// add to path, don't ignore additional paths
			if k == "PATH" {
				c.updatePath(v)
			}
		}
	}
}

func (c *Config) NonEmptyToken() bool {
	return c.Token() != ""
}
func (c *Config) CliSettings() *CliSettings {
	return c.cliSettings
}

func (c *Config) Format() string {
	c.m.Lock()
	defer c.m.Unlock()
	return c.format
}
func (c *Config) CLIDownloadLockFileName() string {
	return filepath.Join(c.cliSettings.DefaultBinaryInstallPath(), "snyk-cli-download.lock")
}
func (c *Config) IsErrorReportingEnabled() bool { return c.isErrorReportingEnabled.Get() }
func (c *Config) IsSnykOssEnabled() bool        { return c.isSnykOssEnabled.Get() }
func (c *Config) IsSnykCodeEnabled() bool       { return c.isSnykCodeEnabled.Get() }
func (c *Config) IsSnykIacEnabled() bool        { return c.isSnykIacEnabled.Get() }
func (c *Config) IsSnykContainerEnabled() bool  { return c.isSnykContainerEnabled.Get() }
func (c *Config) IsSnykAdvisorEnabled() bool    { return c.isSnykAdvisorEnabled.Get() }
func (c *Config) LogPath() string {
	c.m.Lock()
	defer c.m.Unlock()
	return c.logPath
}
func (c *Config) SnykApi() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.snykApiUrl
}

func (c *Config) SnykCodeApi() string {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.snykCodeApiUrl
}

func (c *Config) SnykUi() string {
	c.m.RLock()
	defer c.m.RUnlock()

	snykUiUrl, err := getCustomEndpointUrlFromSnykApi(c.snykApiUrl, "app")
	if err != nil || snykUiUrl == "" {
		return DefaultSnykUiUrl
	}

	return snykUiUrl
}
func (c *Config) SnykCodeAnalysisTimeout() time.Duration { return c.snykCodeAnalysisTimeout }
func (c *Config) IntegrationName() string {
	return c.engine.GetConfiguration().GetString(configuration.INTEGRATION_NAME)
}
func (c *Config) IntegrationVersion() string {
	return c.engine.GetConfiguration().GetString(configuration.INTEGRATION_VERSION)
}
func (c *Config) FilterSeverity() types.SeverityFilter { return c.filterSeverity }
func (c *Config) Token() string {
	c.m.Lock()
	defer c.m.Unlock()
	return c.token
}

// TokenChangesChannel returns a channel that will be written into once the token has changed.
// This allows aborting operations when the token is changed.
func (c *Config) TokenChangesChannel() <-chan string {
	c.m.Lock()
	defer c.m.Unlock()
	channel := make(chan string, 1)
	c.tokenChangeChannels = append(c.tokenChangeChannels, channel)
	return channel
}

func (c *Config) SetCliSettings(settings *CliSettings) {
	c.cliSettings = settings
}

func (c *Config) UpdateApiEndpoints(snykApiUrl string) bool {
	if snykApiUrl == "" {
		c.m.Lock()
		snykApiUrl = DefaultSnykApiUrl
		c.m.Unlock()
	}

	c.engine.GetConfiguration().Set(configuration.API_URL, snykApiUrl)

	if snykApiUrl != c.snykApiUrl {
		c.m.RLock()
		c.snykApiUrl = snykApiUrl
		c.m.RUnlock()

		// Update Code API endpoint
		snykCodeApiUrl, err := getCodeApiUrlFromCustomEndpoint(snykApiUrl)
		if err != nil {
			c.Logger().Error().Err(err).Msg("Couldn't obtain Snyk Code API url from CLI endpoint.")
		}

		c.SetSnykCodeApi(snykCodeApiUrl)
		return true
	}
	return false
}

func (c *Config) SetSnykCodeApi(snykCodeApiUrl string) {
	if snykCodeApiUrl == "" {
		c.snykCodeApiUrl = DefaultDeeproxyApiUrl
		return
	}
	c.m.Lock()
	defer c.m.Unlock()
	c.snykCodeApiUrl = snykCodeApiUrl

	config := c.engine.GetConfiguration()
	additionalURLs := config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	additionalURLs = append(additionalURLs, c.snykCodeApiUrl)
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, additionalURLs)
}

func (c *Config) SetErrorReportingEnabled(enabled bool) { c.isErrorReportingEnabled.Set(enabled) }
func (c *Config) SetSnykOssEnabled(enabled bool)        { c.isSnykOssEnabled.Set(enabled) }
func (c *Config) SetSnykCodeEnabled(enabled bool) {
	c.isSnykCodeEnabled.Set(enabled)
	// the general setting overrules the specific one and should be slowly discontinued
	c.EnableSnykCodeQuality(enabled)
	c.EnableSnykCodeSecurity(enabled)
}
func (c *Config) SetSnykIacEnabled(enabled bool) { c.isSnykIacEnabled.Set(enabled) }

func (c *Config) SetSnykContainerEnabled(enabled bool) { c.isSnykContainerEnabled.Set(enabled) }

func (c *Config) SetSnykAdvisorEnabled(enabled bool) { c.isSnykAdvisorEnabled.Set(enabled) }

func (c *Config) SetSeverityFilter(severityFilter types.SeverityFilter) bool {
	emptySeverityFilter := types.SeverityFilter{}
	if severityFilter == emptySeverityFilter {
		return false
	}

	filterModified := c.filterSeverity != severityFilter
	c.Logger().Debug().Str("method", "SetSeverityFilter").Interface("severityFilter", severityFilter).Msg("Setting severity filter:")
	c.filterSeverity = severityFilter
	return filterModified
}

func (c *Config) SetToken(token string) {
	c.m.Lock()
	oldToken := c.token

	// always update the token and auth method in the engine
	c.token = token
	c.m.Unlock()

	oauthToken, err := c.TokenAsOAuthToken()
	isOauthToken := err == nil
	conf := c.engine.GetConfiguration()

	// propagate token to gaf
	if !isOauthToken && conf.GetString(configuration.AUTHENTICATION_TOKEN) != token {
		c.Logger().Info().Msg("Setting legacy authentication in GAF")
		conf.Set(configuration.AUTHENTICATION_TOKEN, token)
	}

	if isOauthToken && conf.GetString(auth.CONFIG_KEY_OAUTH_TOKEN) != token {
		c.Logger().Info().Err(err).Msg("setting oauth2 authentication in GAF")
		conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, token)
	}

	// ensure scrubbing of new token
	if w, ok := c.scrubbingWriter.(frameworkLogging.ScrubbingLogWriter); ok {
		w.AddTerm(token, 0)
		if isOauthToken {
			w.AddTerm(oauthToken.AccessToken, 0)
			w.AddTerm(oauthToken.RefreshToken, 0)
		}
	}

	// return if the token hasn't changed
	if oldToken == token {
		return
	}

	c.m.Lock()
	for _, channel := range c.tokenChangeChannels {
		select {
		case channel <- token:
		default:
			// Using select and a default case avoids deadlock when the channel is full
			c.Logger().Warn().Msg("Cannot send cancellation to channel - channel is full")
		}
	}
	c.tokenChangeChannels = []chan string{}
	c.m.Unlock()
}

func (c *Config) SetFormat(format string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.format = format
}

func (c *Config) SetLogPath(logPath string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.logPath = logPath
}

func (c *Config) ConfigureLogging(server types.Server) {
	var logLevel zerolog.Level
	var err error

	logLevel, err = zerolog.ParseLevel(c.LogLevel())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Can't set log level from flag. Setting to default (=info)")
		logLevel = zerolog.InfoLevel
	}

	// env var overrides flag
	envLogLevel := os.Getenv("SNYK_LOG_LEVEL")
	if envLogLevel != "" {
		msg := fmt.Sprint("Setting log level from environment variable (SNYK_LOG_LEVEL) \"", envLogLevel, "\"")
		_, _ = fmt.Fprintln(os.Stderr, msg)
		envLevel, levelErr := zerolog.ParseLevel(envLogLevel)
		if levelErr == nil {
			_, _ = fmt.Fprintln(os.Stderr, "Can't set log level from flag. Setting to default (=info)")
			logLevel = envLevel
		}
	}
	c.SetLogLevel(logLevel.String())

	levelWriter := logging.New(server)
	writers := []io.Writer{levelWriter}

	if c.LogPath() != "" {
		c.logFile, err = os.OpenFile(c.LogPath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "couldn't open logfile")
		} else {
			_, _ = fmt.Fprintln(os.Stderr, fmt.Sprint("adding file logger to file ", c.logPath))
			writers = append(writers, c.logFile)
		}
	}

	c.m.Lock()
	defer c.m.Unlock()

	// overwrite a potential already existing writer, so we have the latest settings
	c.scrubbingWriter = frameworkLogging.NewScrubbingWriter(zerolog.MultiLevelWriter(writers...), c.scrubbingDict)
	writer := c.getConsoleWriter(c.scrubbingWriter)
	logger := zerolog.New(writer).With().Timestamp().Str("separator", "-").Str("method", "").Str("ext", "").Logger().Level(logLevel)
	c.logger = &logger
	c.engine.SetLogger(&logger)
}

func (c *Config) getConsoleWriter(writer io.Writer) zerolog.ConsoleWriter {
	w := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = writer
		w.NoColor = true
		w.TimeFormat = time.RFC3339
		w.PartsOrder = []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			"method",
			"ext",
			"separator",
			zerolog.CallerFieldName,
			zerolog.MessageFieldName,
		}
		w.FieldsExclude = []string{"method", "separator", "ext"}
	})
	return w
}

// DisableLoggingToFile closes the open log file and sets the global logger back to it's default
func (c *Config) DisableLoggingToFile() {
	c.Logger().Info().Msgf("Disabling file logging to %v", c.logPath)
	c.logPath = ""
	if c.logFile != nil {
		_ = c.logFile.Close()
	}
}

func (c *Config) SetConfigFile(configFile string) { c.configFile = configFile }

func getCodeApiUrlFromCustomEndpoint(endpoint string) (string, error) {
	// Code API endpoint can be set via env variable for debugging using local API instance
	deeproxyEnvVarUrl := strings.Trim(os.Getenv(deeproxyApiUrlKey), "/")
	if deeproxyEnvVarUrl != "" {
		return deeproxyEnvVarUrl, nil
	}

	if endpoint == "" {
		return DefaultDeeproxyApiUrl, nil
	}

	// Use Snyk API endpoint to determine deeproxy API URL
	return getCustomEndpointUrlFromSnykApi(endpoint, "deeproxy")
}

func getCustomEndpointUrlFromSnykApi(snykApi string, subdomain string) (string, error) {
	snykApiUrl, err := url.Parse(strings.Trim(snykApi, " "))
	if err != nil || !snykApiUrl.IsAbs() {
		return "", err
	}

	m := regexp.MustCompile(`^(ap[pi]\.)?`)
	snykApiUrl.Host = m.ReplaceAllString(snykApiUrl.Host, subdomain+".")
	snykApiUrl.Path = ""

	return snykApiUrl.String(), nil
}

func (c *Config) snykCodeAnalysisTimeoutFromEnv() time.Duration {
	var snykCodeTimeout time.Duration
	var err error
	env := os.Getenv(snykCodeTimeoutKey)
	if env == "" {
		snykCodeTimeout = 12 * time.Hour
	} else {
		snykCodeTimeout, err = time.ParseDuration(env)
		if err != nil {
			c.Logger().Err(err).Msg("couldn't convert timeout env variable to integer")
		}
	}
	return snykCodeTimeout
}

func (c *Config) updatePath(pathExtension string) {
	if pathExtension == "" {
		return
	}
	err := os.Setenv("PATH", os.Getenv("PATH")+pathListSeparator+pathExtension)
	c.m.Lock()
	c.path += pathListSeparator + pathExtension
	c.m.Unlock()
	c.Logger().Debug().Str("method", "updatePath").Msg("updated path with " + pathExtension)
	c.Logger().Debug().Str("method", "updatePath").Msgf("PATH = %s", os.Getenv("PATH"))
	if err != nil {
		c.Logger().Warn().Str("method", "loadFile").Msg("Couldn't update path ")
	}
}

// The order of the files is important - first file variable definitions win!
func (c *Config) configFiles() []string {
	var files []string
	configFile := c.configFile
	if configFile != "" {
		files = append(files, configFile)
	}
	home := os.Getenv("HOME")
	if home == "" {
		home = xdg.Home
	}
	stdFiles := []string{
		".snyk.env",
		home + "/.snyk.env",
	}
	return append(files, stdFiles...)
}

func (c *Config) Organization() string {
	return c.engine.GetConfiguration().GetString(configuration.ORGANIZATION)
}

func (c *Config) SetOrganization(organization string) {
	c.engine.GetConfiguration().Set(configuration.ORGANIZATION, organization)
}

func (c *Config) ManageBinariesAutomatically() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.manageBinariesAutomatically.Get()
}

func (c *Config) SetManageBinariesAutomatically(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.manageBinariesAutomatically.Set(enabled)
}

func (c *Config) ManageCliBinariesAutomatically() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	if c.engine.GetConfiguration().GetString(cli_constants.EXECUTION_MODE_KEY) != cli_constants.EXECUTION_MODE_VALUE_STANDALONE {
		return false
	}
	return c.ManageBinariesAutomatically()
}

func (c *Config) DeviceID() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.deviceId
}

func (c *Config) SetDeviceID(deviceId string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.deviceId = deviceId
}

func (c *Config) ClientCapabilities() types.ClientCapabilities {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.clientCapabilities
}

func (c *Config) SetClientCapabilities(capabilities types.ClientCapabilities) {
	c.m.Lock()
	defer c.m.Unlock()
	c.clientCapabilities = capabilities
}

func (c *Config) Path() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.path
}

func (c *Config) AutomaticAuthentication() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.automaticAuthentication
}

func (c *Config) SetAutomaticAuthentication(value bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.automaticAuthentication = value
}

func (c *Config) SetAutomaticScanning(value bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.automaticScanning = value
}

func (c *Config) addDefaults() {
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS != windows {
		c.updatePath("/usr/local/bin")
		c.updatePath("/bin")
		c.updatePath(xdg.Home + "/bin")
	}
	c.determineJavaHome()
	c.mavenDefaults()
}

func (c *Config) SetIntegrationName(integrationName string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.engine.GetConfiguration().Set(configuration.INTEGRATION_NAME, integrationName)
}

func (c *Config) SetIntegrationVersion(integrationVersion string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.engine.GetConfiguration().Set(configuration.INTEGRATION_VERSION, integrationVersion)
}

func (c *Config) SetIdeName(ideName string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.engine.GetConfiguration().Set(configuration.INTEGRATION_ENVIRONMENT, ideName)
}
func (c *Config) SetIdeVersion(ideVersion string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.engine.GetConfiguration().Set(configuration.INTEGRATION_ENVIRONMENT_VERSION, ideVersion)
}

func (c *Config) TrustedFolders() []string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.trustedFolders
}

func (c *Config) SetTrustedFolders(folderPaths []string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.trustedFolders = folderPaths
}

func (c *Config) IsSnykCodeSecurityEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.activateSnykCodeSecurity
}

func (c *Config) EnableSnykCodeSecurity(activate bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.activateSnykCodeSecurity = activate
}

func (c *Config) IsSnykCodeQualityEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.activateSnykCodeQuality
}

func (c *Config) EnableSnykCodeQuality(activate bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.activateSnykCodeQuality = activate
}

func (c *Config) OsPlatform() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.osPlatform
}

func (c *Config) SetOsPlatform(osPlatform string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.osPlatform = osPlatform
}

func (c *Config) OsArch() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.osArch
}

func (c *Config) SetOsArch(osArch string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.osArch = osArch
}

func (c *Config) RuntimeName() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.runtimeName
}

func (c *Config) SetRuntimeName(runtimeName string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.runtimeName = runtimeName
}

func (c *Config) RuntimeVersion() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.runtimeVersion
}

func (c *Config) SetRuntimeVersion(runtimeVersion string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.runtimeVersion = runtimeVersion
}

func (c *Config) IsAutoScanEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.automaticScanning
}

func (c *Config) Engine() workflow.Engine {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.engine
}

func (c *Config) SetEngine(engine workflow.Engine) {
	c.m.Lock()
	defer c.m.Unlock()
	c.engine = engine
}

func (c *Config) IsSnykLearnCodeActionsEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.enableSnykLearnCodeActions
}

func (c *Config) SetSnykLearnCodeActionsEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.enableSnykLearnCodeActions = enabled
}

func (c *Config) IsSnykOSSQuickFixCodeActionsEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.enableSnykOSSQuickFixCodeActions
}

func (c *Config) SetSnykOSSQuickFixCodeActionsEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.enableSnykOSSQuickFixCodeActions = enabled
}

func (c *Config) IsDeltaFindingsEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.enableDeltaFindings
}

func (c *Config) SetDeltaFindingsEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.enableDeltaFindings = enabled
}

func (c *Config) SetLogLevel(level string) {
	c.m.RLock()
	defer c.m.RUnlock()
	parseLevel, err := zerolog.ParseLevel(level)
	if err == nil {
		zerolog.SetGlobalLevel(parseLevel)
	}
}

func (c *Config) LogLevel() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return zerolog.GlobalLevel().String()
}

func (c *Config) Logger() *zerolog.Logger {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.logger
}

func (c *Config) TokenAsOAuthToken() (oauth2.Token, error) {
	var oauthToken oauth2.Token
	if _, err := uuid.Parse(c.Token()); err == nil {
		const msg = "creds are legacy, not oauth2"
		c.Logger().Trace().Msg(msg)
		return oauthToken, errors.New(msg)
	}
	err := json.Unmarshal([]byte(c.Token()), &oauthToken)
	if err != nil {
		c.Logger().Trace().Err(err).Msg("unable to unmarshal creds to oauth2 token")
		return oauthToken, err
	}
	return oauthToken, nil
}

func (c *Config) Storage() storage.StorageWithCallbacks {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.storage
}

func (c *Config) SetStorage(s storage.StorageWithCallbacks) {
	c.m.Lock()
	defer c.m.Unlock()
	c.storage = s
	c.engine.GetConfiguration().SetStorage(s)
}

func (c *Config) IdeVersion() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.engine.GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT_VERSION)
}
func (c *Config) IdeName() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.engine.GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT)
}

func (c *Config) IsFedramp() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.engine.GetConfiguration().GetBool(configuration.IS_FEDRAMP)
}

func (c *Config) IsAnalyticsPermitted() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	logger := c.Logger().With().Str("method", "IsAnalyticsPermitted").Logger()

	u, err := url.Parse(c.engine.GetConfiguration().GetString(configuration.API_URL))

	if err != nil {
		logger.Error().Err(err).Msg("unable to parse configured API_URL")
		return false
	}

	_, found := analyticsPermittedEnvironments[u.Host]

	return found
}

func (c *Config) SetClientProtocolVersion(requiredProtocolVersion string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.clientProtocolVersion = requiredProtocolVersion
}

func (c *Config) AuthenticationMethod() types.AuthenticationMethod {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.authenticationMethod
}

func (c *Config) SetAuthenticationMethod(authMethod types.AuthenticationMethod) {
	c.m.Lock()
	defer c.m.Unlock()
	c.authenticationMethod = authMethod
}

func (c *Config) IsSnykOpenBrowserActionEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.isOpenBrowserActionEnabled
}

func (c *Config) SetSnykOpenBrowserActionsEnabled(enable bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.isOpenBrowserActionEnabled = enable
}

func (c *Config) FolderConfig(path string) *types.FolderConfig {
	var folderConfig *types.FolderConfig
	var err error
	folderConfig, err = gitconfig.GetOrCreateFolderConfig(path)
	if err != nil {
		folderConfig = &types.FolderConfig{}
	}
	c.m.RLock()
	addParams, ok := c.folderAdditionalParameters[path]
	if ok {
		folderConfig.AdditionalParameters = addParams
	}
	c.m.RUnlock()
	return folderConfig
}

func (c *Config) SetAdditionalParameters(path string, parameters []string) {
	c.m.Lock()
	defer c.m.Unlock()

	c.folderAdditionalParameters[path] = parameters
}

func (c *Config) HoverVerbosity() int {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.hoverVerbosity
}

func (c *Config) SetHoverVerbosity(verbosity int) {
	c.m.Lock()
	defer c.m.Unlock()

	c.hoverVerbosity = verbosity
}

func (c *Config) SetOffline(b bool) {
	c.m.Lock()
	defer c.m.Unlock()

	c.offline = b
}

func (c *Config) Offline() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.offline
}
