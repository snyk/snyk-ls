/*
 * © 2022-2026 Snyk Limited
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
	"github.com/snyk/cli-extension-secrets/pkg/secrets"
	"github.com/spf13/pflag"
	"golang.org/x/oauth2"

	"github.com/snyk/code-client-go/pkg/code"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	ignoreworkflow "github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/pkg/osflows"

	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
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

var _ types.ConfigProvider = (*Config)(nil)

type Config struct {
	scrubbingWriter                     zerolog.LevelWriter
	cliPath                             string
	cliInsecure                         bool
	cliAdditionalOssParameters          []string
	cliReleaseChannel                   string
	configFile                          string
	format                              string
	isSnykAdvisorEnabled                bool // no GAF setting constant; kept on struct
	logPath                             string
	logFile                             *os.File
	snykCodeAnalysisTimeout             time.Duration
	snykApiUrl                          string
	token                               string
	deviceId                            string
	clientCapabilities                  types.ClientCapabilities
	binarySearchPaths                   []string
	tokenChangeChannels                 []chan string
	prepareDefaultEnvChannel            chan bool
	filterSeverity                      types.SeverityFilter
	issueViewOptions                    types.IssueViewOptions
	trustedFolders                      []types.FilePath
	osPlatform                          string
	osArch                              string
	runtimeName                         string
	runtimeVersion                      string
	engine                              workflow.Engine
	logger                              *zerolog.Logger
	storage                             storage.StorageWithCallbacks
	m                                   sync.RWMutex
	clientProtocolVersion               string
	offline                             bool
	ws                                  types.Workspace
	isLSPInitialized                    bool
	cachedOriginalPath                  string
	userSettingsPath                    string
	lastSetOrganization                 string // Trimmed raw org value last passed to SetOrganization
	secureAtInceptionExecutionFrequency string
	ldxSyncConfigCache                  types.LDXSyncConfigCache
	configResolver                      types.ConfigResolverInterface
}

// gafConf returns the GAF Configuration from the engine. Returns nil if the engine is not yet initialized.
func (c *Config) gafConf() configuration.Configuration {
	if c.engine == nil {
		return nil
	}
	return c.engine.GetConfiguration()
}

func (c *Config) gafGetBool(name string) bool {
	conf := c.gafConf()
	if conf == nil {
		return false
	}
	key := configuration.UserGlobalKey(name)
	if conf.IsSet(key) {
		return conf.GetBool(key)
	}
	return conf.GetBool(name)
}

func (c *Config) gafSetBool(name string, value bool) {
	conf := c.gafConf()
	if conf == nil {
		return
	}
	conf.Set(configuration.UserGlobalKey(name), value)
}

func (c *Config) gafGetString(name string) string {
	conf := c.gafConf()
	if conf == nil {
		return ""
	}
	key := configuration.UserGlobalKey(name)
	if conf.IsSet(key) {
		return conf.GetString(key)
	}
	return conf.GetString(name)
}

func (c *Config) gafSetString(name string, value string) {
	conf := c.gafConf()
	if conf == nil {
		return
	}
	conf.Set(configuration.UserGlobalKey(name), value)
}

func (c *Config) gafGetInt(name string) int {
	conf := c.gafConf()
	if conf == nil {
		return 0
	}
	key := configuration.UserGlobalKey(name)
	if conf.IsSet(key) {
		return conf.GetInt(key)
	}
	return conf.GetInt(name)
}

func (c *Config) gafSetInt(name string, value int) {
	conf := c.gafConf()
	if conf == nil {
		return
	}
	conf.Set(configuration.UserGlobalKey(name), value)
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
	c.SetCliPath("")
	c.prepareDefaultEnvChannel = make(chan bool, 1)
	if c.binarySearchPaths == nil {
		c.binarySearchPaths = getDefaultBinarySearchPaths()
	}
	c.configFile = ""
	c.format = FormatMd
	c.snykCodeAnalysisTimeout = c.snykCodeAnalysisTimeoutFromEnv()
	if engine == nil {
		initWorkFlowEngine(c)
	} else {
		// Engine is provided externally, e.g. we were invoked from CLI.
		c.engine = engine
	}

	engineConfig := c.engine.GetConfiguration()
	engineConfig.AddDefaultValue(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, configuration.ImmutableDefaultValueFunction(true))
	engineConfig.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
	engineConfig.Set("configfile", c.configFile)

	// Register all configuration flags so defaults are available via GAF
	fs := pflag.NewFlagSet("snyk-ls-defaults", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = engineConfig.AddFlagSet(fs)

	// Set non-zero defaults on GAF Configuration
	c.gafSetBool(types.SettingSnykOssEnabled, true)
	c.gafSetBool(types.SettingSnykIacEnabled, true)
	c.gafSetBool(types.SettingSendErrorReports, true)
	c.gafSetBool(types.SettingAutomaticDownload, true)
	c.gafSetBool(types.SettingAutomaticAuthentication, true)
	c.gafSetBool(types.SettingTrustEnabled, true)
	c.gafSetBool(types.SettingScanAutomatic, true)
	c.gafSetBool(types.SettingEnableSnykLearnCodeActions, true)
	c.gafSetString(types.SettingAuthenticationMethod, string(types.TokenAuthentication))

	c.deviceId = c.determineDeviceId()
	c.addDefaults()
	c.filterSeverity = types.DefaultSeverityFilter()
	c.issueViewOptions = types.DefaultIssueViewOptions()
	c.UpdateApiEndpoints(DefaultSnykApiUrl)
	c.clientSettingsFromEnv()
	c.gafSetInt("hover_verbosity", 3)
	c.initLdxSyncOrgConfigCache()
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

	err = code.Init(c.engine)
	if err != nil {
		return err
	}

	err = osflows.Init(c.engine)
	if err != nil {
		return err
	}

	err = secrets.Init(c.engine)
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
	return c.gafGetBool(types.SettingTrustEnabled)
}

func (c *Config) SetTrustedFolderFeatureEnabled(enabled bool) {
	c.gafSetBool(types.SettingTrustEnabled, enabled)
}

func (c *Config) NonEmptyToken() bool {
	return c.token != ""
}

func (c *Config) CliInstalled() bool {
	c.m.Lock()
	defer c.m.Unlock()
	stat, err := c.cliPathFileInfo()
	isDirectory := stat != nil && stat.IsDir()
	if isDirectory {
		log.Warn().Msgf("CLI path (%s) refers to a directory and not a file", c.cliPath)
	}
	return c.cliPath != "" && err == nil && !isDirectory
}

func (c *Config) cliPathFileInfo() (os.FileInfo, error) {
	stat, err := os.Stat(c.cliPath)
	if err == nil {
		log.Trace().Str("method", "config.cliPathFileInfo").Msgf("CLI path: %s, Size: %d, Perm: %s",
			c.cliPath,
			stat.Size(),
			stat.Mode().Perm())
	}
	return stat, err
}

func (c *Config) CliIsPathDefined() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.cliPath != ""
}

// CliPath returns the full path to the CLI executable that is stored in the CLI configuration
func (c *Config) CliPath() string {
	c.m.Lock()
	defer c.m.Unlock()
	return filepath.Clean(c.cliPath)
}

func (c *Config) SetCliPath(path string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.cliPath = path
}

func (c *Config) CliDefaultBinaryInstallPath() string {
	lsPath := filepath.Join(xdg.DataHome, "snyk-ls")
	err := os.MkdirAll(lsPath, 0o755)
	if err != nil {
		log.Err(err).Str("method", "lsPath").Msgf("couldn't create %s", lsPath)
		return ""
	}
	return lsPath
}

func (c *Config) CliInsecure() bool {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.cliInsecure
}

func (c *Config) SetCliInsecure(insecure bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.cliInsecure = insecure
}

func (c *Config) CliAdditionalOssParameters() []string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.cliAdditionalOssParameters
}

func (c *Config) SetCliAdditionalOssParameters(params []string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.cliAdditionalOssParameters = params
}

func (c *Config) Format() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.format
}

func (c *Config) CLIDownloadLockFileName() (string, error) {
	c.m.Lock()
	defer c.m.Unlock()
	var path string
	if c.cliPath == "" {
		c.cliPath = c.CliDefaultBinaryInstallPath()
	}
	path = filepath.Dir(c.cliPath)
	err := os.MkdirAll(path, 0o755)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "snyk-cli-download.lock"), nil
}

func (c *Config) IsErrorReportingEnabled() bool {
	return c.gafGetBool(types.SettingSendErrorReports)
}

func (c *Config) IsSnykOssEnabled() bool {
	return c.gafGetBool(types.SettingSnykOssEnabled)
}

func (c *Config) IsSnykCodeEnabled() bool {
	return c.gafGetBool(types.SettingSnykCodeEnabled)
}

func (c *Config) IsSnykIacEnabled() bool {
	return c.gafGetBool(types.SettingSnykIacEnabled)
}

func (c *Config) IsSnykSecretsEnabled() bool {
	return c.gafGetBool(types.SettingSnykSecretsEnabled)
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
	return c.gafGetString(types.SettingBinaryBaseUrl)
}

func (c *Config) SetCliBaseDownloadURL(cliBaseDownloadURL string) {
	c.gafSetString(types.SettingBinaryBaseUrl, cliBaseDownloadURL)
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
	return c.gafGetInt(types.SettingRiskScoreThreshold)
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

func (c *Config) UpdateApiEndpoints(snykApiUrl string) bool {
	if snykApiUrl == "" {
		snykApiUrl = DefaultSnykApiUrl
	}

	if snykApiUrl != c.snykApiUrl {
		c.m.Lock()
		c.snykApiUrl = snykApiUrl
		c.m.Unlock()

		// update configuration
		cfg := c.engine.GetConfiguration()
		cfg.Set(configuration.API_URL, snykApiUrl)
		cfg.Set(configuration.WEB_APP_URL, c.SnykUI())
		return true
	}
	return false
}

func (c *Config) SetErrorReportingEnabled(enabled bool) {
	c.gafSetBool(types.SettingSendErrorReports, enabled)
}

func (c *Config) SetSnykOssEnabled(enabled bool) {
	c.gafSetBool(types.SettingSnykOssEnabled, enabled)
}

func (c *Config) SetSnykCodeEnabled(enabled bool) {
	c.gafSetBool(types.SettingSnykCodeEnabled, enabled)
}

func (c *Config) SetSnykIacEnabled(enabled bool) {
	c.gafSetBool(types.SettingSnykIacEnabled, enabled)
}

func (c *Config) SetSnykSecretsEnabled(enabled bool) {
	c.gafSetBool(types.SettingSnykSecretsEnabled, enabled)
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
	c.logger.Trace().Str("method", "SetSeverityFilter").Interface("severityFilter", severityFilter).Msg("Setting severity filter")
	c.filterSeverity = *severityFilter
	return filterModified
}

func (c *Config) SetRiskScoreThreshold(riskScoreThreshold *int) bool {
	if riskScoreThreshold == nil {
		return false
	}
	modified := c.gafGetInt(types.SettingRiskScoreThreshold) != *riskScoreThreshold
	c.Logger().Trace().Str("method", "SetRiskScoreThreshold").Int("riskScoreThreshold", *riskScoreThreshold).Msg("Setting risk score threshold")
	c.gafSetInt(types.SettingRiskScoreThreshold, *riskScoreThreshold)
	return modified
}

func (c *Config) SetIssueViewOptions(issueViewOptions *types.IssueViewOptions) bool {
	c.m.Lock()
	defer c.m.Unlock()
	if issueViewOptions == nil {
		return false
	}
	issueViewOptionsModified := c.issueViewOptions != *issueViewOptions
	c.logger.Trace().Str("method", "SetIssueViewOptions").Interface("issueViewOptions", issueViewOptions).Msg("Setting issue view options")
	c.issueViewOptions = *issueViewOptions
	return issueViewOptionsModified
}

func (c *Config) SetToken(newTokenString string) {
	c.m.Lock()
	defer c.m.Unlock()

	conf := c.engine.GetConfiguration()
	oldTokenString := c.token

	newOAuthToken, oAuthErr := getAsOauthToken(newTokenString, c.logger)

	if c.AuthenticationMethod() == types.OAuthAuthentication && oAuthErr == nil &&
		c.shouldUpdateOAuth2Token(oldTokenString, newTokenString) {
		c.logger.Debug().Msg("put oauth2 token into configuration")
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
		conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, newTokenString)
	} else if conf.GetString(configuration.AUTHENTICATION_TOKEN) != newTokenString {
		c.logger.Debug().Msg("put api token or pat into configuration")
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
	return c.engine.GetConfiguration().GetString(configuration.ORGANIZATION)
}

func (c *Config) SetOrganization(organization string) {
	c.m.Lock()
	defer c.m.Unlock()

	organization = strings.TrimSpace(organization)

	// Skip if we're setting the exact same value as before to prevent redundant API calls.
	// Prevents re-resolving a slug and re-resolving "" to the user's preferred default org in the web UI.
	if organization == c.lastSetOrganization {
		return
	}

	c.engine.GetConfiguration().Set(configuration.ORGANIZATION, organization)
	c.lastSetOrganization = organization
}

func (c *Config) ManageBinariesAutomatically() bool {
	return c.gafGetBool(types.SettingAutomaticDownload)
}

func (c *Config) SetManageBinariesAutomatically(enabled bool) {
	c.gafSetBool(types.SettingAutomaticDownload, enabled)
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
	return c.gafGetBool(types.SettingAutomaticAuthentication)
}

func (c *Config) SetAutomaticAuthentication(value bool) {
	c.gafSetBool(types.SettingAutomaticAuthentication, value)
}

func (c *Config) SetAutomaticScanning(value bool) {
	c.gafSetBool(types.SettingScanAutomatic, value)
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
	return c.gafGetBool(types.SettingScanAutomatic)
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
	return c.gafGetBool(types.SettingEnableSnykLearnCodeActions)
}

func (c *Config) SetSnykLearnCodeActionsEnabled(enabled bool) {
	c.gafSetBool(types.SettingEnableSnykLearnCodeActions, enabled)
}

func (c *Config) IsSnykOSSQuickFixCodeActionsEnabled() bool {
	return c.gafGetBool(types.SettingEnableSnykOssQuickFixActions)
}

func (c *Config) SetSnykOSSQuickFixCodeActionsEnabled(enabled bool) {
	c.gafSetBool(types.SettingEnableSnykOssQuickFixActions, enabled)
}

func (c *Config) IsDeltaFindingsEnabled() bool {
	return c.gafGetBool(types.SettingScanNetNew)
}

// SetDeltaFindingsEnabled sets deltaFindings config and returns true if value changed
func (c *Config) SetDeltaFindingsEnabled(enabled bool) bool {
	modified := c.gafGetBool(types.SettingScanNetNew) != enabled
	c.gafSetBool(types.SettingScanNetNew, enabled)
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
	method := c.AuthenticationMethod()

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
	return types.AuthenticationMethod(c.gafGetString(types.SettingAuthenticationMethod))
}

func (c *Config) SetAuthenticationMethod(authMethod types.AuthenticationMethod) {
	c.gafSetString(types.SettingAuthenticationMethod, string(authMethod))
}

func (c *Config) IsSnykOpenBrowserActionEnabled() bool {
	return c.gafGetBool(types.SettingEnableSnykOpenBrowserActions)
}

func (c *Config) SetSnykOpenBrowserActionsEnabled(enable bool) {
	c.gafSetBool(types.SettingEnableSnykOpenBrowserActions, enable)
}

// FolderConfig gets or creates a new folder config for the given folder path.
// Can cause a rewrite to storage. For read-only operations where we know the stored data is complete, use
// ImmutableFolderConfig instead.
func (c *Config) FolderConfig(path types.FilePath) *types.FolderConfig {
	folderConfig, err := storedconfig.GetOrCreateFolderConfig(c.engine.GetConfiguration(), path, c.Logger())
	if err != nil {
		c.logger.Err(err).Msg("unable to get or create folder config")
		return c.getMinimalFolderConfig(path)
	}
	c.attachConfigResolver(folderConfig)
	return folderConfig
}

// ImmutableFolderConfig returns the folder config for a path without writing to storage or enriching from Git.
// This is suitable for read-only configuration checks. If no config exists in storage, this creates one with default
// values (OrgSetByUser=false, FeatureFlags initialized) but does not persist it.
func (c *Config) ImmutableFolderConfig(path types.FilePath) *types.FolderConfig {
	folderConfig, err := storedconfig.GetFolderConfigWithOptions(c.engine.GetConfiguration(), path, c.Logger(), storedconfig.GetFolderConfigOptions{
		CreateIfNotExist: true,
		ReadOnly:         true,
		EnrichFromGit:    true,
	})
	if err != nil {
		c.logger.Err(err).Msg("unable to get or create folder config")
		return c.getMinimalFolderConfig(path)
	}
	c.attachConfigResolver(folderConfig)
	return folderConfig
}

// getMinimalFolderConfig returns a folder config with only the path set, and no other fields. Used as a fallback
// when a folder config cannot be retrieved from storage.
func (c *Config) getMinimalFolderConfig(path types.FilePath) *types.FolderConfig {
	fc := &types.FolderConfig{FolderPath: path}
	c.attachConfigResolver(fc)
	return fc
}

// attachConfigResolver sets the ConfigResolver on the FolderConfig.
// Falls back to a direct configuration wrapper if no ConfigResolver is available.
func (c *Config) attachConfigResolver(fc *types.FolderConfig) {
	if resolver := c.GetConfigResolver(); resolver != nil {
		fc.ConfigResolver = resolver
	} else {
		fc.SetConf(c.engine.GetConfiguration())
	}
}

func (c *Config) UpdateFolderConfig(folderConfig *types.FolderConfig) error {
	return storedconfig.UpdateFolderConfig(c.engine.GetConfiguration(), folderConfig, c.logger)
}

func (c *Config) BatchUpdateFolderConfigs(folderConfigs []*types.FolderConfig) error {
	return storedconfig.BatchUpdateFolderConfigs(c.engine.GetConfiguration(), folderConfigs, c.logger)
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
// the folder, it returns the global organization (which if unset, configuration will return the default org).
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

	return c.FolderConfigOrganization(fc)
}

// FolderConfigOrganization returns the organization configured for a given folderConfig.
// When folderConfig has Conf() set (e.g. from delta scan with a temp config), reads from that.
// Otherwise falls back to the engine's configuration.
func (c *Config) FolderConfigOrganization(folderConfig *types.FolderConfig) string {
	logger := c.Logger().With().Str("method", "FolderConfigOrganization").Logger()
	if folderConfig == nil {
		globalOrg := c.Organization()
		logger.Trace().
			Str("method", "FolderConfigOrganization").
			Str("globalOrg", globalOrg).Msg("no folder config given, falling back to global organization")
		return globalOrg
	}

	logger = logger.With().Str("folderConfig for path", string(folderConfig.FolderPath)).Logger()

	conf := folderConfig.Conf()
	if conf == nil {
		conf = c.Engine().GetConfiguration()
	}
	snapshot := types.ReadFolderConfigSnapshot(conf, folderConfig.FolderPath)

	if snapshot.OrgSetByUser {
		if snapshot.PreferredOrg == "" {
			return c.Organization()
		}
		return snapshot.PreferredOrg
	}

	// If AutoDeterminedOrg is empty, fall back to global organization
	if snapshot.AutoDeterminedOrg == "" {
		globalOrg := c.Organization()
		logger.Trace().Str("globalOrg", globalOrg).Msg("AutoDeterminedOrg is empty, falling back to global organization")
		return globalOrg
	}
	return snapshot.AutoDeterminedOrg
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
// If it's a slug, it uses configuration to resolve it to a UUID.
func (c *Config) ResolveOrgToUUID(org string) (string, error) {
	// Check if the organization is already a valid UUID
	if _, err := uuid.Parse(org); err == nil {
		// It's already a UUID, return it
		return org, nil
	}

	// It's not a UUID, so it might be a slug. Use configuration to resolve it.
	// When we set ORGANIZATION to a slug, configuration will resolve it to a UUID via its default value function
	engineConfig := c.Engine().GetConfiguration()
	clonedConfig := engineConfig.Clone()
	clonedConfig.Set(configuration.ORGANIZATION, org)
	resolvedOrg := clonedConfig.GetString(configuration.ORGANIZATION)

	// Verify the resolved value is a UUID
	if _, err := uuid.Parse(resolvedOrg); err != nil {
		return "", fmt.Errorf("organization '%s' could not be resolved to a valid UUID: %w", org, err)
	}

	return resolvedOrg, nil
}

func (c *Config) HoverVerbosity() int {
	return c.gafGetInt("hover_verbosity")
}

func (c *Config) SetHoverVerbosity(verbosity int) {
	c.gafSetInt("hover_verbosity", verbosity)
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
	return c.gafGetBool(types.SettingAutoConfigureMcpServer)
}

func (c *Config) SetAutoConfigureMcpEnabled(enabled bool) {
	c.gafSetBool(types.SettingAutoConfigureMcpServer, enabled)
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

func (c *Config) CodeEndpoint() string {
	return c.gafGetString(types.SettingCodeEndpoint)
}

func (c *Config) SetCodeEndpoint(endpoint string) {
	c.gafSetString(types.SettingCodeEndpoint, endpoint)
}

func (c *Config) ProxyHttp() string {
	return c.gafGetString(types.SettingProxyHttp)
}

func (c *Config) SetProxyHttp(proxy string) {
	c.gafSetString(types.SettingProxyHttp, proxy)
}

func (c *Config) ProxyHttps() string {
	return c.gafGetString(types.SettingProxyHttps)
}

func (c *Config) SetProxyHttps(proxy string) {
	c.gafSetString(types.SettingProxyHttps, proxy)
}

func (c *Config) ProxyNoProxy() string {
	return c.gafGetString(types.SettingProxyNoProxy)
}

func (c *Config) SetProxyNoProxy(noProxy string) {
	c.gafSetString(types.SettingProxyNoProxy, noProxy)
}

func (c *Config) IsProxyInsecure() bool {
	return c.gafGetBool(types.SettingProxyInsecure)
}

func (c *Config) SetProxyInsecure(insecure bool) {
	c.gafSetBool(types.SettingProxyInsecure, insecure)
}

func (c *Config) IsPublishSecurityAtInceptionRulesEnabled() bool {
	return c.gafGetBool(types.SettingPublishSecurityAtInceptionRules)
}

func (c *Config) SetPublishSecurityAtInceptionRulesEnabled(enabled bool) {
	c.gafSetBool(types.SettingPublishSecurityAtInceptionRules, enabled)
}

func (c *Config) CliReleaseChannel() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.cliReleaseChannel
}

func (c *Config) SetCliReleaseChannel(channel string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.cliReleaseChannel = channel
}

// initLdxSyncOrgConfigCache initializes the LDX-Sync org config cache
func (c *Config) initLdxSyncOrgConfigCache() {
	c.m.Lock()
	defer c.m.Unlock()
	c.ldxSyncConfigCache = *types.NewLDXSyncConfigCache()
}

// GetLdxSyncOrgConfigCache returns the LDX-Sync org config cache.
// The returned cache is safe for concurrent use.
func (c *Config) GetLdxSyncOrgConfigCache() *types.LDXSyncConfigCache {
	c.m.RLock()
	defer c.m.RUnlock()
	return &c.ldxSyncConfigCache
}

// UpdateLdxSyncOrgConfig updates the org config cache with a new org config
func (c *Config) UpdateLdxSyncOrgConfig(orgConfig *types.LDXSyncOrgConfig) {
	c.ldxSyncConfigCache.SetOrgConfig(orgConfig)
}

func (c *Config) SetConfigResolver(resolver types.ConfigResolverInterface) {
	c.m.Lock()
	defer c.m.Unlock()
	c.configResolver = resolver
}

func (c *Config) GetConfigResolver() types.ConfigResolverInterface {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.configResolver
}
