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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
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
	"github.com/xtgo/uuid"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/infrastructure/cli/filename"
	"github.com/snyk/snyk-ls/internal/logging"
	"github.com/snyk/snyk-ls/internal/storage"
	storedConfig "github.com/snyk/snyk-ls/internal/storedconfig"
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
		c.C.Logger().Trace().Str("method", "config.cliSettings.Installed").Msgf("CLI path: %s, Size: %d, Perm: %s",
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
	scrubbingWriter                  zerolog.LevelWriter
	cliSettings                      *CliSettings
	configFile                       string
	format                           string
	isErrorReportingEnabled          bool
	isSnykCodeEnabled                bool
	isSnykOssEnabled                 bool
	isSnykIacEnabled                 bool
	isSnykContainerEnabled           bool
	isSnykAdvisorEnabled             bool
	manageBinariesAutomatically      bool
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
	trustedFolders                   []types.FilePath
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
	hoverVerbosity                   int
	offline                          bool
	ws                               types.Workspace
	mcpServerEnabled                 bool
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

func New() *Config {
	return newConfig(nil)
}

func NewFromExtension(engine workflow.Engine) *Config {
	return newConfig(engine)
}

// New creates a configuration object with default values
func newConfig(engine workflow.Engine) *Config {
	c := &Config{}
	c.logger = getNewScrubbingLogger(c)
	c.cliSettings = NewCliSettings(c)
	c.automaticAuthentication = true
	c.configFile = ""
	c.format = FormatMd
	c.isErrorReportingEnabled = true
	c.isSnykOssEnabled = true
	c.isSnykIacEnabled = true
	c.manageBinariesAutomatically = true
	c.logPath = ""
	c.snykCodeAnalysisTimeout = c.snykCodeAnalysisTimeoutFromEnv()
	c.token = ""
	c.trustedFoldersFeatureEnabled = true
	c.automaticScanning = true
	c.authenticationMethod = types.TokenAuthentication
	if engine == nil {
		initWorkFlowEngine(c)
	} else {
		c.engine = engine
	}
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

	conf := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	conf.PersistInStorage(storedConfig.ConfigMainKey)
	conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
	enableOAuth := c.authenticationMethod == types.OAuthAuthentication
	conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, enableOAuth)
	conf.Set("configfile", c.configFile)

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
	c.scrubbingWriter = frameworkLogging.NewScrubbingWriter(logging.New(nil), make(frameworkLogging.ScrubbingDict))
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
func (c *Config) CLIDownloadLockFileName() (string, error) {
	c.cliSettings.cliPathAccessMutex.Lock()
	defer c.cliSettings.cliPathAccessMutex.Unlock()
	var path string
	if c.cliSettings.cliPath == "" {
		c.cliSettings.cliPath = c.cliSettings.DefaultBinaryInstallPath()
	}
	path = filepath.Dir(c.cliSettings.cliPath)
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "snyk-cli-download.lock"), nil
}

func (c *Config) IsErrorReportingEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.isErrorReportingEnabled
}

func (c *Config) IsSnykOssEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.isSnykOssEnabled
}

func (c *Config) IsSnykCodeEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.isSnykCodeEnabled || c.activateSnykCodeSecurity || c.activateSnykCodeQuality
}

func (c *Config) IsSnykIacEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.isSnykIacEnabled
}

func (c *Config) IsSnykContainerEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.isSnykContainerEnabled
}

func (c *Config) IsSnykAdvisorEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.isSnykAdvisorEnabled
}

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

func (c *Config) SnykUI() string {
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
	c.m.Lock()
	defer c.m.Unlock()

	c.cliSettings = settings
}

func (c *Config) UpdateApiEndpoints(snykApiUrl string) bool {
	if snykApiUrl == "" {
		snykApiUrl = DefaultSnykApiUrl
	}

	if snykApiUrl != c.snykApiUrl {
		c.m.Lock()
		c.snykApiUrl = snykApiUrl
		c.m.Unlock()

		// update GAF
		cfg := c.engine.GetConfiguration()
		cfg.Set(configuration.API_URL, snykApiUrl)
		cfg.Set(configuration.WEB_APP_URL, c.SnykUI())

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
	c.m.Lock()
	defer c.m.Unlock()

	if snykCodeApiUrl == "" {
		c.snykCodeApiUrl = DefaultDeeproxyApiUrl
		return
	}
	c.snykCodeApiUrl = snykCodeApiUrl

	config := c.engine.GetConfiguration()
	additionalURLs := config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	additionalURLs = append(additionalURLs, c.snykCodeApiUrl)
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, additionalURLs)
}

func (c *Config) SetErrorReportingEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()

	c.isErrorReportingEnabled = enabled
}

func (c *Config) SetSnykOssEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()

	c.isSnykOssEnabled = enabled
}

func (c *Config) SetSnykCodeEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()

	c.isSnykCodeEnabled = enabled
	// the general setting overrules the specific one and should be slowly discontinued
	c.activateSnykCodeQuality = enabled
	c.activateSnykCodeSecurity = enabled
}
func (c *Config) SetSnykIacEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()

	c.isSnykIacEnabled = enabled
}

func (c *Config) SetSnykContainerEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()

	c.isSnykContainerEnabled = enabled
}

func (c *Config) SetSnykAdvisorEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.isSnykAdvisorEnabled = enabled
}

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

func (c *Config) SetToken(newTokenString string) {
	c.m.Lock()
	defer c.m.Unlock()

	conf := c.engine.GetConfiguration()
	oldTokenString := c.token

	newOAuthToken, err := getAsOauthToken(newTokenString, c.logger)
	isNewOauthToken := err == nil

	// propagate newTokenString to gaf
	if !isNewOauthToken && conf.GetString(configuration.AUTHENTICATION_TOKEN) != newTokenString {
		c.logger.Info().Msg("Setting legacy authentication in GAF")
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, false)
		conf.Set(configuration.AUTHENTICATION_TOKEN, newTokenString)
	}

	if c.shouldUpdateOAuth2Token(oldTokenString, newTokenString) {
		c.logger.Info().Err(err).Msg("setting oauth2 authentication in GAF")
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
		conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, newTokenString)
	}

	// ensure scrubbing of new newTokenString
	if w, ok := c.scrubbingWriter.(frameworkLogging.ScrubbingLogWriter); ok {
		w.AddTerm(newTokenString, 0)
		if newOAuthToken != nil {
			w.AddTerm(newOAuthToken.AccessToken, 0)
			w.AddTerm(newOAuthToken.RefreshToken, 0)
		}
	}

	c.token = newTokenString
	c.notifyTokenChannelListeners(newTokenString, oldTokenString)
}

func (c *Config) notifyTokenChannelListeners(newTokenString string, oldTokenString string) {
	if oldTokenString != newTokenString {
		for _, channel := range c.tokenChangeChannels {
			select {
			case channel <- newTokenString:
			default:
				// Using select and a default case avoids deadlock when the channel is full
				c.logger.Warn().Msg("Cannot send cancellation to channel - channel is full")
			}
		}
		c.tokenChangeChannels = []chan string{}
	}
}

// shouldUpdateOAuth2Token checks if a new token should cause an update in language server.
func (c *Config) shouldUpdateOAuth2Token(oldToken string, newToken string) bool {
	if newToken == "" {
		return true
	}

	newOauthToken, err := getAsOauthToken(newToken, c.logger)
	if err != nil {
		return false
	}

	oldOauthToken, err := getAsOauthToken(oldToken, c.logger)
	if err != nil {
		return true
	}

	isNewToken := oldToken != newToken
	tokenExpiryIsNewer := oldOauthToken.Expiry.Before(newOauthToken.Expiry)

	return isNewToken && tokenExpiryIsNewer
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
	c.scrubbingWriter = frameworkLogging.NewScrubbingWriter(zerolog.MultiLevelWriter(writers...), make(frameworkLogging.ScrubbingDict))
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

func (c *Config) Organization() string {
	return c.engine.GetConfiguration().GetString(configuration.ORGANIZATION)
}

func (c *Config) SetOrganization(organization string) {
	c.engine.GetConfiguration().Set(configuration.ORGANIZATION, organization)
}

func (c *Config) ManageBinariesAutomatically() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.manageBinariesAutomatically
}

func (c *Config) SetManageBinariesAutomatically(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.manageBinariesAutomatically = enabled
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
		envvars.UpdatePath("/usr/local/bin", false)
		envvars.UpdatePath("/bin", false)
		envvars.UpdatePath(xdg.Home+"/bin", false)
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

func (c *Config) TrustedFolders() []types.FilePath {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.trustedFolders
}

func (c *Config) SetTrustedFolders(folderPaths []types.FilePath) {
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

// SetDeltaFindingsEnabled sets deltaFindings config and returns true if value changed
func (c *Config) SetDeltaFindingsEnabled(enabled bool) bool {
	c.m.Lock()
	defer c.m.Unlock()
	modified := c.enableDeltaFindings != enabled
	c.enableDeltaFindings = enabled
	return modified
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
	token := c.Token()

	oauthToken, err := getAsOauthToken(token, c.logger)
	if err != nil || oauthToken == nil {
		return oauth2.Token{}, err
	}

	return *oauthToken, nil
}

func getAsOauthToken(token string, logger *zerolog.Logger) (*oauth2.Token, error) {
	if _, err := uuid.Parse(token); err == nil {
		const msg = "creds are legacy, not oauth2"
		logger.Trace().Msg(msg)
		return nil, errors.New(msg)
	}

	var oauthToken oauth2.Token
	err := json.Unmarshal([]byte(token), &oauthToken)
	if err != nil {
		logger.Trace().Err(err).Msg("unable to unmarshal creds to oauth2 token")
		return nil, err
	}
	return &oauthToken, nil
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

	conf := c.engine.GetConfiguration()
	conf.PersistInStorage(storedConfig.ConfigMainKey)
	conf.SetStorage(s)
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

func (c *Config) FolderConfig(path types.FilePath) *types.FolderConfig {
	var folderConfig *types.FolderConfig
	var err error
	folderConfig, err = storedConfig.GetOrCreateFolderConfig(c.engine.GetConfiguration(), path)
	if err != nil {
		folderConfig = &types.FolderConfig{FolderPath: path}
	}
	return folderConfig
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

func (c *Config) Workspace() types.Workspace {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.ws
}

func (c *Config) SetWorkspace(workspace types.Workspace) {
	c.m.Lock()
	defer c.m.Unlock()

	c.ws = workspace
}

func (c *Config) McpServerEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.mcpServerEnabled
}
