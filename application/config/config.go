/*
 * © 2022-2025 Snyk Limited
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

// Package config implements the configuration functionality
package config

import (
	"context"
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
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"

	"github.com/snyk/cli-extension-os-flows/pkg/osflows"
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
	ignoreworkflow "github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/infrastructure/cli/filename"
	"github.com/snyk/snyk-ls/internal/logging"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	DeeproxyApiUrlKey     = "DEEPROXY_API_URL"
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
	stat, err := c.cliPathFileInfo()
	isDirectory := stat != nil && stat.IsDir()
	if isDirectory {
		c.C.Logger().Warn().Msgf("CLI path (%s) refers to a directory and not a file", c.cliPath)
	}
	return c.cliPath != "" && err == nil && !isDirectory
}

// cliPathFileInfo returns file info for the CLI path.
func (c *CliSettings) cliPathFileInfo() (os.FileInfo, error) {
	stat, err := os.Stat(c.cliPath)
	if err == nil {
		c.C.Logger().Trace().Str("method", "config.cliSettings.cliPathFileInfo").Msgf("CLI path: %s, Size: %d, Perm: %s",
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
	err := os.MkdirAll(lsPath, 0o755)
	if err != nil {
		c.C.Logger().Err(err).Str("method", "lsPath").Msgf("couldn't create %s", lsPath)
		return ""
	}
	return lsPath
}

type Config struct {
	scrubbingWriter                     zerolog.LevelWriter
	cliSettings                         *CliSettings
	configFile                          string
	format                              string
	isErrorReportingEnabled             bool
	isSnykCodeEnabled                   bool
	isSnykOssEnabled                    bool
	isSnykIacEnabled                    bool
	isSnykAdvisorEnabled                bool
	manageBinariesAutomatically         bool
	logPath                             string
	logFile                             *os.File
	snykCodeAnalysisTimeout             time.Duration
	snykApiUrl                          string
	cliBaseDownloadURL                  string
	token                               string
	deviceId                            string
	clientCapabilities                  types.ClientCapabilities
	binarySearchPaths                   []string
	automaticAuthentication             bool
	tokenChangeChannels                 []chan string
	prepareDefaultEnvChannel            chan bool
	filterSeverity                      types.SeverityFilter
	riskScoreThreshold                  int
	issueViewOptions                    types.IssueViewOptions
	trustedFolders                      []types.FilePath
	trustedFoldersFeatureEnabled        bool
	activateSnykCodeSecurity            bool
	osPlatform                          string
	osArch                              string
	runtimeName                         string
	runtimeVersion                      string
	automaticScanning                   bool
	authenticationMethod                types.AuthenticationMethod
	engine                              workflow.Engine
	enableSnykLearnCodeActions          bool
	enableSnykOSSQuickFixCodeActions    bool
	enableDeltaFindings                 bool
	logger                              *zerolog.Logger
	storage                             storage.StorageWithCallbacks
	m                                   sync.RWMutex
	clientProtocolVersion               string
	isOpenBrowserActionEnabled          bool
	hoverVerbosity                      int
	offline                             bool
	ws                                  types.Workspace
	isLSPInitialized                    bool
	cachedOriginalPath                  string
	userSettingsPath                    string
	autoConfigureMcpEnabled             bool
	secureAtInceptionExecutionFrequency string
	ldxSyncConfigCache                  *types.LDXSyncConfigCache
	ldxSyncConfigCacheMutex             sync.RWMutex
	configResolver                      *types.ConfigResolver
	cachedDefaultOrg                    string
	cachedDefaultOrgMutex               sync.RWMutex
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

func New(opts ...ConfigOption) *Config {
	return newConfig(nil, opts...)
}

func NewFromExtension(engine workflow.Engine, opts ...ConfigOption) *Config {
	return newConfig(engine, opts...)
}

// New creates a configuration object with default values
func newConfig(engine workflow.Engine, opts ...ConfigOption) *Config {
	c := &Config{}

	for _, opt := range opts {
		opt(c)
	}

	c.logger = getNewScrubbingLogger(c)
	c.cliSettings = NewCliSettings(c)
	c.prepareDefaultEnvChannel = make(chan bool, 1)
	if c.binarySearchPaths == nil {
		c.binarySearchPaths = getDefaultBinarySearchPaths()
	}
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
		// Engine is provided externally, e.g. we were invoked from CLI.
		c.engine = engine
	}

	gafConfig := c.engine.GetConfiguration()
	gafConfig.AddDefaultValue(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, configuration.ImmutableDefaultValueFunction(true))
	gafConfig.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
	gafConfig.Set("configfile", c.configFile)
	c.deviceId = c.determineDeviceId()
	c.addDefaults()
	c.filterSeverity = types.DefaultSeverityFilter()
	c.issueViewOptions = types.DefaultIssueViewOptions()
	c.UpdateApiEndpoints(DefaultSnykApiUrl)
	c.enableSnykLearnCodeActions = true
	c.clientSettingsFromEnv()
	c.hoverVerbosity = 3
	return c
}

func initWorkFlowEngine(c *Config) {
	c.m.Lock()
	defer c.m.Unlock()

	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())

	conf.PersistInStorage(storedconfig.ConfigMainKey)
	conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
	c.engine = app.CreateAppEngineWithOptions(app.WithConfiguration(conf), app.WithZeroLogger(c.logger))

	err := initWorkflows(c)
	if err != nil {
		// we use the global logger, as we are in config setup, so we don't want to cause a deadlock
		log.Err(err).Msg("unable to initialize workflows")
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

func initWorkflows(c *Config) error {
	err := localworkflows.InitWhoAmIWorkflow(c.engine)
	if err != nil {
		return err
	}

	err = ignoreworkflow.InitIgnoreWorkflows(c.engine)
	if err != nil {
		return err
	}

	err = localworkflows.InitCodeWorkflow(c.engine)
	if err != nil {
		return err
	}

	err = osflows.Init(c.engine)
	if err != nil {
		return err
	}

	return nil
}

func getNewScrubbingLogger(c *Config) *zerolog.Logger {
	c.m.Lock()
	defer c.m.Unlock()
	c.scrubbingWriter = frameworkLogging.NewScrubbingWriter(logging.New(nil), make(frameworkLogging.ScrubbingDict))
	writer := c.getConsoleWriter(c.scrubbingWriter)
	logger := zerolog.New(writer).With().Timestamp().Str("separator", "-").Str("method", "").Str("ext", "").Logger()
	return &logger
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
			return uuid.NewString()
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
	return c.token != ""
}

func (c *Config) CliSettings() *CliSettings {
	return c.cliSettings
}

func (c *Config) Format() string {
	c.m.RLock()
	defer c.m.RUnlock()
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
	err := os.MkdirAll(path, 0o755)
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

	return c.isSnykCodeEnabled || c.activateSnykCodeSecurity
}

func (c *Config) IsSnykIacEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.isSnykIacEnabled
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

func (c *Config) Endpoint() string {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.snykApiUrl
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

func (c *Config) CliBaseDownloadURL() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.cliBaseDownloadURL
}

func (c *Config) SetCliBaseDownloadURL(cliBaseDownloadURL string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.cliBaseDownloadURL = cliBaseDownloadURL
}

func (c *Config) SnykCodeAnalysisTimeout() time.Duration { return c.snykCodeAnalysisTimeout }
func (c *Config) IntegrationName() string {
	return c.engine.GetConfiguration().GetString(configuration.INTEGRATION_NAME)
}

func (c *Config) IntegrationVersion() string {
	return c.engine.GetConfiguration().GetString(configuration.INTEGRATION_VERSION)
}

func (c *Config) FilterSeverity() types.SeverityFilter {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.filterSeverity
}

func (c *Config) RiskScoreThreshold() int {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.riskScoreThreshold
}

func (c *Config) IssueViewOptions() types.IssueViewOptions {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.issueViewOptions
}

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

// IsDefaultEnvReady whether the default environment has been prepared or not.
func (c *Config) IsDefaultEnvReady() bool {
	select {
	case <-c.prepareDefaultEnvChannel:
		return true
	default:
		return false
	}
}

// WaitForDefaultEnv blocks until the default environment has been prepared
// or until the provided context is canceled. Returns the context error if it is done.
func (c *Config) WaitForDefaultEnv(ctx context.Context) error {
	select {
	case <-c.prepareDefaultEnvChannel:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
		return true
	}
	return false
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
	c.activateSnykCodeSecurity = enabled
}

func (c *Config) SetSnykIacEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()

	c.isSnykIacEnabled = enabled
}

func (c *Config) SetSnykAdvisorEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.isSnykAdvisorEnabled = enabled
}

func (c *Config) SetSeverityFilter(severityFilter *types.SeverityFilter) bool {
	c.m.Lock()
	defer c.m.Unlock()
	if severityFilter == nil {
		return false
	}
	filterModified := c.filterSeverity != *severityFilter
	c.logger.Debug().Str("method", "SetSeverityFilter").Interface("severityFilter", severityFilter).Msg("Setting severity filter")
	c.filterSeverity = *severityFilter
	return filterModified
}

func (c *Config) SetRiskScoreThreshold(riskScoreThreshold *int) bool {
	c.m.Lock()
	defer c.m.Unlock()
	if riskScoreThreshold == nil {
		return false
	}
	modified := c.riskScoreThreshold != *riskScoreThreshold
	c.logger.Debug().Str("method", "SetRiskScoreThreshold").Int("riskScoreThreshold", *riskScoreThreshold).Msg("Setting risk score threshold")
	c.riskScoreThreshold = *riskScoreThreshold
	return modified
}

func (c *Config) SetIssueViewOptions(issueViewOptions *types.IssueViewOptions) bool {
	c.m.Lock()
	defer c.m.Unlock()
	if issueViewOptions == nil {
		return false
	}
	issueViewOptionsModified := c.issueViewOptions != *issueViewOptions
	c.logger.Debug().Str("method", "SetIssueViewOptions").Interface("issueViewOptions", issueViewOptions).Msg("Setting issue view options")
	c.issueViewOptions = *issueViewOptions
	return issueViewOptionsModified
}

func (c *Config) SetToken(newTokenString string) {
	c.m.Lock()
	defer c.m.Unlock()

	conf := c.engine.GetConfiguration()
	oldTokenString := c.token

	newOAuthToken, oAuthErr := getAsOauthToken(newTokenString, c.logger)

	if c.authenticationMethod == types.OAuthAuthentication && oAuthErr == nil &&
		c.shouldUpdateOAuth2Token(oldTokenString, newTokenString) {
		c.logger.Debug().Msg("put oauth2 token into GAF")
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
		conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, newTokenString)
	} else if conf.GetString(configuration.AUTHENTICATION_TOKEN) != newTokenString {
		c.logger.Debug().Msg("put api token or pat into GAF")
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, false)
		conf.Set(configuration.AUTHENTICATION_TOKEN, newTokenString) // We use the same config key for PATs and API Tokens.
	}

	// ensure scrubbing of new newTokenString
	if w, ok := c.scrubbingWriter.(frameworkLogging.ScrubbingLogWriter); ok {
		if newTokenString != "" {
			w.AddTerm(newTokenString, 0)
			if newOAuthToken != nil && newOAuthToken.AccessToken != "" {
				w.AddTerm(newOAuthToken.AccessToken, 0)
				w.AddTerm(newOAuthToken.RefreshToken, 0)
			}
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
		c.logFile, err = os.OpenFile(c.LogPath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
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
		w.TimeFormat = time.RFC3339Nano
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

func (c *Config) GetCodeApiUrlFromCustomEndpoint(sastResponse *sast_contract.SastResponse) (string, error) {
	// Code API sastResponse can be set via env variable for debugging using local API instance
	deeproxyEnvVarUrl := strings.Trim(os.Getenv(DeeproxyApiUrlKey), "/")
	if deeproxyEnvVarUrl != "" {
		c.logger.Debug().Str("deeproxyEnvVarUrl", deeproxyEnvVarUrl).Msg("using deeproxy env variable for code api url")
		return deeproxyEnvVarUrl, nil
	}

	if sastResponse != nil && sastResponse.SastEnabled && sastResponse.LocalCodeEngine.Enabled {
		return sastResponse.LocalCodeEngine.Url, nil
	}

	// Use Snyk API endpoint to determine deeproxy API URL
	return getCustomEndpointUrlFromSnykApi(c.Endpoint(), "deeproxy")
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

// Deprecated use FolderOrganization(path) to get organization per folder
func (c *Config) Organization() string {
	// Check cache first to avoid GAF API calls
	if cached := c.getCachedOrg(); cached != "" {
		return cached
	}

	// Get from GAF (may trigger API call if not set)
	org := c.engine.GetConfiguration().GetString(configuration.ORGANIZATION)

	// Cache the result if non-empty
	if org != "" {
		c.setCachedOrg(org)
	}

	return org
}

func (c *Config) getCachedOrg() string {
	c.cachedDefaultOrgMutex.RLock()
	defer c.cachedDefaultOrgMutex.RUnlock()
	return c.cachedDefaultOrg
}

func (c *Config) setCachedOrg(org string) {
	c.cachedDefaultOrgMutex.Lock()
	defer c.cachedDefaultOrgMutex.Unlock()
	c.cachedDefaultOrg = org
}

func (c *Config) SetOrganization(organization string) {
	c.engine.GetConfiguration().Set(configuration.ORGANIZATION, organization)
	// Clear cache so next call picks up the new value
	c.ClearCachedGlobalOrg()
}

// ClearCachedGlobalOrg clears the cached global org.
// Call this when org configuration changes (e.g., after LDX-Sync refresh or SetOrganization).
func (c *Config) ClearCachedGlobalOrg() {
	c.setCachedOrg("")
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
	go func() {
		defer close(c.prepareDefaultEnvChannel)
		//goland:noinspection GoBoolExpressions
		if runtime.GOOS != "windows" {
			envvars.UpdatePath("/usr/local/bin", false)
			envvars.UpdatePath("/bin", false)
			envvars.UpdatePath(xdg.Home+"/bin", false)
		}
		c.determineJavaHome()
		c.mavenDefaults()
		c.setCachedOriginalPath()
	}()
}

func (c *Config) GetCachedOriginalPath() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.cachedOriginalPath
}

func (c *Config) setCachedOriginalPath() {
	c.m.Lock()
	defer c.m.Unlock()
	c.cachedOriginalPath = os.Getenv("PATH")
}

func (c *Config) GetUserSettingsPath() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.userSettingsPath
}

func (c *Config) SetUserSettingsPath(userSettingsPath string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.userSettingsPath = userSettingsPath
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

func (c *Config) AuthenticationMethodMatchesCredentials() bool {
	token := c.Token()
	method := c.authenticationMethod

	if method == types.FakeAuthentication {
		return true // We allow any value for the token in unit tests which use FakeAuthentication.
	}

	var derivedMethod types.AuthenticationMethod
	if len(token) == 0 {
		derivedMethod = types.EmptyAuthenticationMethod
	} else if auth.IsAuthTypePAT(token) {
		derivedMethod = types.PatAuthentication
	} else if auth.IsAuthTypeToken(token) {
		derivedMethod = types.TokenAuthentication
	} else {
		_, err := getAsOauthToken(token, c.logger)
		if err == nil {
			derivedMethod = types.OAuthAuthentication
		}
	}

	return method == derivedMethod
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
	c.storage = s

	conf := c.engine.GetConfiguration()
	conf.SetStorage(s)
	c.m.Unlock()
	conf.PersistInStorage(storedconfig.ConfigMainKey)
	conf.PersistInStorage(auth.CONFIG_KEY_OAUTH_TOKEN)
	conf.PersistInStorage(configuration.AUTHENTICATION_TOKEN)

	// now refresh from storage
	err := s.Refresh(conf, storedconfig.ConfigMainKey)
	if err != nil {
		c.logger.Err(err).Msg("unable to load stored config")
	}

	// During storage initialization, create config if it doesn't exist
	sc, err := storedconfig.GetStoredConfig(conf, c.logger, false)
	c.logger.Debug().Any("storedConfig", sc).Send()

	if err != nil {
		c.logger.Err(err).Msg("unable to load stored config")
	}

	// refresh token if in storage
	if c.EmptyToken() {
		err = s.Refresh(conf, auth.CONFIG_KEY_OAUTH_TOKEN)
		if err != nil {
			c.logger.Err(err).Msg("unable to refresh storage")
		}
		err = s.Refresh(conf, configuration.AUTHENTICATION_TOKEN)
		if err != nil {
			c.logger.Err(err).Msg("unable to refresh storage")
		}
	}
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

// FolderConfig gets or creates a new folder config for the given folder path.
// Will cause a rewrite to storage, for read-only operations, use FolderConfigReadOnly instead.
func (c *Config) FolderConfig(path types.FilePath) *types.FolderConfig {
	folderConfig, err := storedconfig.GetOrCreateFolderConfig(c.engine.GetConfiguration(), path, c.Logger())
	if err != nil {
		c.logger.Err(err).Msg("unable to get or create folder config")
		return c.getMinimalFolderConfig(path)
	}
	return folderConfig
}

// FolderConfigReadOnly returns the folder config for a path without writing to storage
// or enriching from Git. This is suitable for read-only configuration checks.
// If no config exists in storage, creates one in-memory with proper default initialization
// (OrgMigratedFromGlobalConfig=true, OrgSetByUser=false, FeatureFlags initialized) but does not persist it.
func (c *Config) FolderConfigReadOnly(path types.FilePath) *types.FolderConfig {
	folderConfig, err := storedconfig.GetFolderConfigWithOptions(c.engine.GetConfiguration(), path, c.Logger(), storedconfig.GetFolderConfigOptions{
		CreateIfNotExist: true,
		ReadOnly:         true,
		EnrichFromGit:    false,
	})
	if err != nil {
		c.logger.Err(err).Msg("unable to get or create folder config")
		return c.getMinimalFolderConfig(path)
	}
	return folderConfig
}

// getMinimalFolderConfig returns a folder config with only the path set, and no other fields. Used as a fallback
// when a folder config cannot be retrieved from storage.
func (c *Config) getMinimalFolderConfig(path types.FilePath) *types.FolderConfig {
	return &types.FolderConfig{FolderPath: path}
}

func (c *Config) UpdateFolderConfig(folderConfig *types.FolderConfig) error {
	return storedconfig.UpdateFolderConfig(c.engine.GetConfiguration(), folderConfig, c.logger)
}

// FolderConfigForSubPath returns the folder config for the workspace folder containing the given path.
// The path parameter can be a subdirectory or file within a workspace folder.
// Returns an error if the workspace is nil or if no workspace folder contains the path.
func (c *Config) FolderConfigForSubPath(path types.FilePath) (*types.FolderConfig, error) {
	if c.Workspace() == nil {
		return nil, fmt.Errorf("workspace is nil, so cannot determine folder config for path: %s", path)
	}

	workspaceFolder := c.Workspace().GetFolderContaining(path)
	if workspaceFolder == nil {
		return nil, fmt.Errorf("no workspace folder found for path: %s", path)
	}

	folderConfig := c.FolderConfig(workspaceFolder.Path())
	return folderConfig, nil
}

// FolderOrganization returns the organization configured for a given folder path. If no organization is configured for
// the folder, it returns the global organization (which if unset, GAF will return the default org).
func (c *Config) FolderOrganization(path types.FilePath) string {
	logger := c.Logger().With().Str("method", "FolderOrganization").Str("path", string(path)).Logger()
	if path == "" {
		globalOrg := c.Organization()
		logger.Warn().Str("globalOrg", globalOrg).Msg("called with empty path, falling back to global organization")
		return globalOrg
	}

	fc, err := storedconfig.GetFolderConfigWithOptions(c.engine.GetConfiguration(), path, c.Logger(), storedconfig.GetFolderConfigOptions{
		CreateIfNotExist: false,
		ReadOnly:         true,
		EnrichFromGit:    false,
	})
	if err != nil {
		globalOrg := c.Organization()
		logger.Warn().Err(err).Str("globalOrg", globalOrg).Msg("error getting folder config, falling back to global organization")
		return globalOrg
	}
	if fc == nil {
		globalOrg := c.Organization()
		logger.Debug().Str("globalOrg", globalOrg).Msg("no folder config in storage, falling back to global organization")
		return globalOrg
	}

	if fc.OrgSetByUser {
		if fc.PreferredOrg == "" {
			return c.Organization()
		} else {
			return fc.PreferredOrg
		}
	} else {
		// If AutoDeterminedOrg is empty, fall back to global organization
		if fc.AutoDeterminedOrg == "" {
			globalOrg := c.Organization()
			logger.Debug().Str("globalOrg", globalOrg).Msg("AutoDeterminedOrg is empty, falling back to global organization")
			return globalOrg
		}
		return fc.AutoDeterminedOrg
	}
}

func (c *Config) FolderOrganizationSlug(path types.FilePath) string {
	clonedConfig := c.Engine().GetConfiguration()
	clonedConfig.Set(configuration.ORGANIZATION, c.FolderOrganization(path))
	return clonedConfig.GetString(configuration.ORGANIZATION_SLUG)
}

// FolderOrganizationForSubPath returns the organization for the workspace folder containing the given path.
// Returns an error if the workspace is nil, if no folder contains the path, or if no organization can be determined.
func (c *Config) FolderOrganizationForSubPath(path types.FilePath) (string, error) {
	if c.Workspace() == nil {
		return "", fmt.Errorf("workspace is nil, so cannot determine organization for path: %s", path)
	}

	workspaceFolder := c.Workspace().GetFolderContaining(path)
	if workspaceFolder == nil {
		return "", fmt.Errorf("cannot determine organization, no workspace folder found for path: %s", path)
	}

	folderOrg := c.FolderOrganization(workspaceFolder.Path())
	if folderOrg == "" {
		return "", fmt.Errorf("no organization was able to be determined for folder: %s", workspaceFolder.Path())
	}

	return folderOrg, nil
}

// ResolveOrgToUUID takes an organization value (which could be a UUID or a slug)
// and returns the UUID. If the input is already a UUID, it returns it unchanged.
// If it's a slug, it uses GAF configuration to resolve it to a UUID.
func (c *Config) ResolveOrgToUUID(org string) (string, error) {
	// Check if the organization is already a valid UUID
	if _, err := uuid.Parse(org); err == nil {
		// It's already a UUID, return it
		return org, nil
	}

	// It's not a UUID, so it might be a slug. Use GAF to resolve it.
	// When we set ORGANIZATION to a slug, GAF will resolve it to a UUID via its default value function
	gafConfig := c.Engine().GetConfiguration()
	clonedConfig := gafConfig.Clone()
	clonedConfig.Set(configuration.ORGANIZATION, org)
	resolvedOrg := clonedConfig.GetString(configuration.ORGANIZATION)

	// Verify the resolved value is a UUID
	if _, err := uuid.Parse(resolvedOrg); err != nil {
		return "", fmt.Errorf("organization '%s' could not be resolved to a valid UUID: %w", org, err)
	}

	return resolvedOrg, nil
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

func (c *Config) IsLSPInitialized() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.isLSPInitialized
}

func (c *Config) SetLSPInitialized(initialized bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.isLSPInitialized = initialized
}

func (c *Config) EmptyToken() bool {
	return !c.NonEmptyToken()
}

func (c *Config) IsAutoConfigureMcpEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.autoConfigureMcpEnabled
}

func (c *Config) SetAutoConfigureMcpEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.autoConfigureMcpEnabled = enabled
}

func (c *Config) GetSecureAtInceptionExecutionFrequency() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.secureAtInceptionExecutionFrequency
}

func (c *Config) SetSecureAtInceptionExecutionFrequency(frequency string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.secureAtInceptionExecutionFrequency = frequency
}

// InitLdxSyncOrgConfigCache initializes the LDX-Sync org config cache and ConfigResolver
func (c *Config) InitLdxSyncOrgConfigCache() {
	c.ldxSyncConfigCacheMutex.Lock()
	defer c.ldxSyncConfigCacheMutex.Unlock()
	c.ldxSyncConfigCache = types.NewLDXSyncConfigCache()
	c.configResolver = types.NewConfigResolver(c.ldxSyncConfigCache, nil, c, c.logger)
}

// GetLdxSyncOrgConfigCache returns the LDX-Sync org config cache, initializing it if needed
func (c *Config) GetLdxSyncOrgConfigCache() *types.LDXSyncConfigCache {
	c.ldxSyncConfigCacheMutex.RLock()
	if c.ldxSyncConfigCache != nil {
		defer c.ldxSyncConfigCacheMutex.RUnlock()
		return c.ldxSyncConfigCache
	}
	c.ldxSyncConfigCacheMutex.RUnlock()

	// Upgrade to write lock for initialization
	c.ldxSyncConfigCacheMutex.Lock()
	defer c.ldxSyncConfigCacheMutex.Unlock()
	// Double-check after acquiring write lock
	if c.ldxSyncConfigCache == nil {
		c.ldxSyncConfigCache = types.NewLDXSyncConfigCache()
		c.configResolver = types.NewConfigResolver(c.ldxSyncConfigCache, nil, c, c.logger)
	}
	return c.ldxSyncConfigCache
}

// GetConfigResolver returns the ConfigResolver for reading configuration values, initializing it if needed
func (c *Config) GetConfigResolver() *types.ConfigResolver {
	c.ldxSyncConfigCacheMutex.RLock()
	if c.configResolver != nil {
		defer c.ldxSyncConfigCacheMutex.RUnlock()
		return c.configResolver
	}
	c.ldxSyncConfigCacheMutex.RUnlock()

	// Upgrade to write lock for initialization
	c.ldxSyncConfigCacheMutex.Lock()
	defer c.ldxSyncConfigCacheMutex.Unlock()
	// Double-check after acquiring write lock
	if c.configResolver == nil {
		if c.ldxSyncConfigCache == nil {
			c.ldxSyncConfigCache = types.NewLDXSyncConfigCache()
		}
		c.configResolver = types.NewConfigResolver(c.ldxSyncConfigCache, nil, c, c.logger)
	}
	return c.configResolver
}

// UpdateLdxSyncOrgConfig updates the org config cache with a new org config
func (c *Config) UpdateLdxSyncOrgConfig(orgConfig *types.LDXSyncOrgConfig) {
	c.ldxSyncConfigCacheMutex.Lock()
	defer c.ldxSyncConfigCacheMutex.Unlock()
	if c.ldxSyncConfigCache == nil {
		c.ldxSyncConfigCache = types.NewLDXSyncConfigCache()
	}
	c.ldxSyncConfigCache.SetOrgConfig(orgConfig)
}

// ClearLdxSyncConfigCache clears the LDX-Sync config cache (called on logout/cleanup)
func (c *Config) ClearLdxSyncConfigCache() {
	c.ldxSyncConfigCacheMutex.Lock()
	defer c.ldxSyncConfigCacheMutex.Unlock()
	c.ldxSyncConfigCache = types.NewLDXSyncConfigCache()
}

// UpdateLdxSyncMachineConfig updates the machine-wide LDX-Sync config in the ConfigResolver
func (c *Config) UpdateLdxSyncMachineConfig(machineConfig map[string]*types.LDXSyncField) {
	c.ldxSyncConfigCacheMutex.Lock()
	defer c.ldxSyncConfigCacheMutex.Unlock()
	if c.configResolver != nil {
		c.configResolver.SetLDXSyncMachineConfig(machineConfig)
	}
}

// GetLdxSyncMachineConfig returns the machine-wide LDX-Sync config from the ConfigResolver
func (c *Config) GetLdxSyncMachineConfig() map[string]*types.LDXSyncField {
	c.ldxSyncConfigCacheMutex.RLock()
	defer c.ldxSyncConfigCacheMutex.RUnlock()
	if c.configResolver != nil {
		return c.configResolver.GetLDXSyncMachineConfig()
	}
	return nil
}

// UpdateGlobalSettingsInResolver updates the global settings reference in ConfigResolver
// This should be called when settings are received from the IDE
func (c *Config) UpdateGlobalSettingsInResolver(settings *types.Settings) {
	c.ldxSyncConfigCacheMutex.Lock()
	defer c.ldxSyncConfigCacheMutex.Unlock()
	if c.configResolver != nil {
		c.configResolver.SetGlobalSettings(settings)
	}
}

// =============================================================================
// Folder-Aware Config Accessors
// These methods use ConfigResolver to get effective values based on LDX-Sync org config and user overrides
// =============================================================================

// FilterSeverityForFolder returns the effective severity filter for a folder,
// considering LDX-Sync org config and user overrides.
func (c *Config) FilterSeverityForFolder(folderConfig *types.FolderConfig) types.SeverityFilter {
	resolver := c.GetConfigResolver()
	if resolver == nil {
		return c.FilterSeverity() // fallback to global
	}
	val, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
	// Only use resolver value if it came from LDX-Sync or user override
	if source != types.ConfigSourceDefault {
		if filter, ok := val.(*types.SeverityFilter); ok && filter != nil {
			return *filter
		}
	}
	return c.FilterSeverity() // fallback to global
}

// RiskScoreThresholdForFolder returns the effective risk score threshold for a folder,
// considering LDX-Sync org config and user overrides.
func (c *Config) RiskScoreThresholdForFolder(folderConfig *types.FolderConfig) int {
	resolver := c.GetConfigResolver()
	if resolver == nil {
		return c.RiskScoreThreshold() // fallback to global
	}
	val, source := resolver.GetValue(types.SettingRiskScoreThreshold, folderConfig)
	// Only use resolver value if it came from LDX-Sync or user override
	if source != types.ConfigSourceDefault {
		if threshold, ok := val.(int); ok {
			return threshold
		}
	}
	return c.RiskScoreThreshold() // fallback to global
}

// IssueViewOptionsForFolder returns the effective issue view options for a folder,
// considering LDX-Sync org config and user overrides.
func (c *Config) IssueViewOptionsForFolder(folderConfig *types.FolderConfig) types.IssueViewOptions {
	resolver := c.GetConfigResolver()
	if resolver == nil {
		return c.IssueViewOptions() // fallback to global
	}

	openIssues, openSource := resolver.GetValue(types.SettingIssueViewOpenIssues, folderConfig)
	ignoredIssues, ignoredSource := resolver.GetValue(types.SettingIssueViewIgnoredIssues, folderConfig)

	// Start with global config values as base
	result := c.IssueViewOptions()

	// Only override if resolver returned a non-default value (i.e., from LDX-Sync or user override)
	if openSource != types.ConfigSourceDefault {
		if open, ok := openIssues.(bool); ok {
			result.OpenIssues = open
		}
	}
	if ignoredSource != types.ConfigSourceDefault {
		if ignored, ok := ignoredIssues.(bool); ok {
			result.IgnoredIssues = ignored
		}
	}
	return result
}

// IsAutoScanEnabledForFolder returns whether automatic scanning is enabled for a folder,
// considering LDX-Sync org config and user overrides.
func (c *Config) IsAutoScanEnabledForFolder(folderConfig *types.FolderConfig) bool {
	resolver := c.GetConfigResolver()
	if resolver == nil {
		return c.IsAutoScanEnabled() // fallback to global
	}
	val, source := resolver.GetValue(types.SettingScanAutomatic, folderConfig)
	if source != types.ConfigSourceDefault {
		if enabled, ok := val.(bool); ok {
			return enabled
		}
	}
	return c.IsAutoScanEnabled() // fallback to global
}

// IsDeltaFindingsEnabledForFolder returns whether delta findings is enabled for a folder,
// considering LDX-Sync org config and user overrides.
func (c *Config) IsDeltaFindingsEnabledForFolder(folderConfig *types.FolderConfig) bool {
	resolver := c.GetConfigResolver()
	if resolver == nil {
		return c.IsDeltaFindingsEnabled() // fallback to global
	}
	val, source := resolver.GetValue(types.SettingScanNetNew, folderConfig)
	if source != types.ConfigSourceDefault {
		if enabled, ok := val.(bool); ok {
			return enabled
		}
	}
	return c.IsDeltaFindingsEnabled() // fallback to global
}

// isProductEnabled is a private helper to check product enablement for a folder.
func (c *Config) isProductEnabled(folderConfig *types.FolderConfig, productName string, fallback func() bool) bool {
	resolver := c.GetConfigResolver()
	if resolver == nil {
		return fallback()
	}
	val, source := resolver.GetValue(types.SettingEnabledProducts, folderConfig)
	if source != types.ConfigSourceDefault {
		if products, ok := val.([]string); ok && len(products) > 0 {
			for _, p := range products {
				if p == productName {
					return true
				}
			}
			return false
		}
	}
	return fallback()
}

// IsSnykCodeEnabledForFolder returns whether Snyk Code is enabled for a folder config,
// considering LDX-Sync org config and user overrides.
func (c *Config) IsSnykCodeEnabledForFolder(folderConfig *types.FolderConfig) bool {
	return c.isProductEnabled(folderConfig, "code", c.IsSnykCodeEnabled)
}

// IsSnykOssEnabledForFolder returns whether Snyk OSS is enabled for a folder config,
// considering LDX-Sync org config and user overrides.
func (c *Config) IsSnykOssEnabledForFolder(folderConfig *types.FolderConfig) bool {
	return c.isProductEnabled(folderConfig, "oss", c.IsSnykOssEnabled)
}

// IsSnykIacEnabledForFolder returns whether Snyk IaC is enabled for a folder config,
// considering LDX-Sync org config and user overrides.
func (c *Config) IsSnykIacEnabledForFolder(folderConfig *types.FolderConfig) bool {
	return c.isProductEnabled(folderConfig, "iac", c.IsSnykIacEnabled)
}

// IsSnykCodeSecurityEnabledForFolder returns whether Snyk Code Security is enabled for a folder config,
// considering LDX-Sync org config and user overrides.
func (c *Config) IsSnykCodeSecurityEnabledForFolder(folderConfig *types.FolderConfig) bool {
	return c.isProductEnabled(folderConfig, "code_security", c.IsSnykCodeSecurityEnabled)
}
