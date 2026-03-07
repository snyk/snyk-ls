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

// GetLogLevel returns the current zerolog global level as a string.
func GetLogLevel() string {
	return zerolog.GlobalLevel().String()
}

// SetLogLevel sets the zerolog global level from a string.
func SetLogLevel(level string) {
	parseLevel, err := zerolog.ParseLevel(level)
	if err == nil {
		zerolog.SetGlobalLevel(parseLevel)
	}
}

// GetAuthenticationMethodFromConfig returns the authentication method from the given configuration.
func GetAuthenticationMethodFromConfig(conf configuration.Configuration) types.AuthenticationMethod {
	return types.AuthenticationMethod(conf.GetString(configuration.UserGlobalKey(types.SettingAuthenticationMethod)))
}

// ManageCliBinariesAutomatically returns true if CLI binaries should be managed automatically (standalone mode + setting enabled).
func ManageCliBinariesAutomatically(conf configuration.Configuration) bool {
	if conf.GetString(cli_constants.EXECUTION_MODE_KEY) != cli_constants.EXECUTION_MODE_VALUE_STANDALONE {
		return false
	}
	return conf.GetBool(configuration.UserGlobalKey(types.SettingAutomaticDownload))
}

// GetFilterSeverity returns the severity filter from the given configuration.
func GetFilterSeverity(conf configuration.Configuration) types.SeverityFilter {
	return types.GetFilterSeverityFromConfig(conf)
}

// SetSeverityFilterOnConfig sets the severity filter on the given configuration. Returns true if the filter was modified.
func SetSeverityFilterOnConfig(conf configuration.Configuration, severityFilter *types.SeverityFilter, logger *zerolog.Logger) bool {
	return types.SetSeverityFilterOnConfig(conf, severityFilter, logger)
}

// GetIssueViewOptions returns the issue view options from the given configuration.
func GetIssueViewOptions(conf configuration.Configuration) types.IssueViewOptions {
	return types.GetIssueViewOptionsFromConfig(conf)
}

// SetIssueViewOptionsOnConfig sets the issue view options on the given configuration. Returns true if options were modified.
func SetIssueViewOptionsOnConfig(conf configuration.Configuration, opts *types.IssueViewOptions, logger *zerolog.Logger) bool {
	return types.SetIssueViewOptionsOnConfig(conf, opts, logger)
}

// GetSnykUI returns the Snyk UI URL from the given configuration.
func GetSnykUI(conf configuration.Configuration) string {
	snykApiUrl := conf.GetString(configuration.UserGlobalKey(types.SettingApiEndpoint))
	snykUiUrl, err := getCustomEndpointUrlFromSnykApi(snykApiUrl, "app")
	if err != nil || snykUiUrl == "" {
		return DefaultSnykUiUrl
	}
	return snykUiUrl
}

// GetSnykCodeAnalysisTimeout returns the Snyk Code analysis timeout from the given configuration.
func GetSnykCodeAnalysisTimeout(conf configuration.Configuration) time.Duration {
	if v, ok := conf.Get(configuration.UserGlobalKey(types.SettingSnykCodeAnalysisTimeout)).(time.Duration); ok {
		return v
	}
	return 12 * time.Hour
}

// SnykCodeAnalysisTimeoutFromEnv returns the Snyk Code analysis timeout from the SNYK_CODE_TIMEOUT environment variable.
func SnykCodeAnalysisTimeoutFromEnv(logger *zerolog.Logger) time.Duration {
	var snykCodeTimeout time.Duration
	var err error
	env := os.Getenv(snykCodeTimeoutKey)
	if env == "" {
		snykCodeTimeout = 12 * time.Hour
	} else {
		snykCodeTimeout, err = time.ParseDuration(env)
		if err != nil {
			logger.Err(err).Msg("couldn't convert timeout env variable to integer")
		}
	}
	return snykCodeTimeout
}

// ParseOAuthToken parses a token string as an OAuth2 token.
// Returns an error if the token is a legacy UUID or invalid JSON.
func ParseOAuthToken(token string, logger *zerolog.Logger) (oauth2.Token, error) {
	oauthToken, err := getAsOauthToken(token, logger)
	if err != nil || oauthToken == nil {
		return oauth2.Token{}, err
	}
	return *oauthToken, nil
}

// GetFolderConfigFromEngine retrieves or creates a folder config and attaches the engine and resolver.
func GetFolderConfigFromEngine(engine workflow.Engine, resolver types.ConfigResolverInterface, path types.FilePath, logger *zerolog.Logger) *types.FolderConfig {
	conf := engine.GetConfiguration()
	folderConfig, err := storedconfig.GetOrCreateFolderConfig(conf, path, logger)
	if err != nil {
		logger.Err(err).Msg("unable to get or create folder config")
		folderConfig = &types.FolderConfig{FolderPath: path}
	}
	wireConfigResolver(folderConfig, engine, resolver)
	return folderConfig
}

// GetImmutableFolderConfigFromEngine returns a read-only folder config without writing to storage.
func GetImmutableFolderConfigFromEngine(engine workflow.Engine, resolver types.ConfigResolverInterface, path types.FilePath, logger *zerolog.Logger) *types.FolderConfig {
	conf := engine.GetConfiguration()
	folderConfig, err := storedconfig.GetFolderConfigWithOptions(conf, path, logger, storedconfig.GetFolderConfigOptions{
		CreateIfNotExist: true,
		ReadOnly:         true,
		EnrichFromGit:    true,
	})
	if err != nil {
		logger.Err(err).Msg("unable to get or create folder config")
		folderConfig = &types.FolderConfig{FolderPath: path}
	}
	wireConfigResolver(folderConfig, engine, resolver)
	return folderConfig
}

func wireConfigResolver(fc *types.FolderConfig, engine workflow.Engine, resolver types.ConfigResolverInterface) {
	fc.Engine = engine
	if resolver != nil {
		fc.ConfigResolver = resolver
	} else {
		fc.SetConf(engine.GetConfiguration())
	}
}

// WriteTokenToConfig writes a token string to the GAF configuration, handling OAuth vs legacy token placement.
// Returns the old token string for comparison by callers that need change detection.
func WriteTokenToConfig(conf configuration.Configuration, authMethod types.AuthenticationMethod, newTokenString string, logger *zerolog.Logger) string {
	key := configuration.UserGlobalKey(types.SettingToken)
	var oldTokenString string
	if conf.IsSet(key) {
		oldTokenString = conf.GetString(key)
	} else {
		oldTokenString = conf.GetString(configuration.AUTHENTICATION_TOKEN)
		if oldTokenString == "" {
			oldTokenString = conf.GetString(auth.CONFIG_KEY_OAUTH_TOKEN)
		}
	}

	newOAuthToken, oAuthErr := getAsOauthToken(newTokenString, logger)

	conf.Set(configuration.UserGlobalKey(types.SettingToken), newTokenString)

	if authMethod == types.OAuthAuthentication && oAuthErr == nil &&
		shouldUpdateToken(oldTokenString, newTokenString, logger) {
		logger.Debug().Msg("put oauth2 token into configuration")
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
		conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, newTokenString)
	} else if conf.GetString(configuration.AUTHENTICATION_TOKEN) != newTokenString {
		logger.Debug().Msg("put api token or pat into configuration")
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, false)
		conf.Set(configuration.AUTHENTICATION_TOKEN, newTokenString)
	}

	_ = newOAuthToken // used by callers for scrubbing
	return oldTokenString
}

func shouldUpdateToken(oldToken string, newToken string, logger *zerolog.Logger) bool {
	if newToken == "" {
		return true
	}

	newOauthToken, err := getAsOauthToken(newToken, logger)
	if err != nil {
		return false
	}

	oldOauthToken, err := getAsOauthToken(oldToken, logger)
	if err != nil {
		return true
	}

	isNewToken := oldToken != newToken
	tokenExpiryIsNewer := oldOauthToken.Expiry.Before(newOauthToken.Expiry)

	return isNewToken && tokenExpiryIsNewer
}

// ResolveOrgToUUIDWithEngine resolves an organization value (UUID or slug) to a UUID using the engine's configuration.
func ResolveOrgToUUIDWithEngine(engine workflow.Engine, org string) (string, error) {
	if _, err := uuid.Parse(org); err == nil {
		return org, nil
	}
	clonedConfig := engine.GetConfiguration().Clone()
	clonedConfig.Set(configuration.ORGANIZATION, org)
	resolvedOrg := clonedConfig.GetString(configuration.ORGANIZATION)
	if _, err := uuid.Parse(resolvedOrg); err != nil {
		return "", fmt.Errorf("organization '%s' could not be resolved to a valid UUID: %w", org, err)
	}
	return resolvedOrg, nil
}

// IsAnalyticsPermittedForAPI checks if analytics are permitted based on the API URL.
func IsAnalyticsPermittedForAPI(apiURL string) bool {
	u, err := url.Parse(apiURL)
	if err != nil {
		return false
	}
	_, found := analyticsPermittedEnvironments[u.Host]
	return found
}

// UpdateApiEndpointsOnConfig updates API endpoint URLs on the given GAF configuration.
// Returns true if the endpoint actually changed.
func UpdateApiEndpointsOnConfig(conf configuration.Configuration, snykApiUrl string) bool {
	if snykApiUrl == "" {
		snykApiUrl = DefaultSnykApiUrl
	}
	current := conf.GetString(configuration.UserGlobalKey(types.SettingApiEndpoint))
	if snykApiUrl != current {
		conf.Set(configuration.UserGlobalKey(types.SettingApiEndpoint), snykApiUrl)
		conf.Set(configuration.API_URL, snykApiUrl)
		snykUiUrl, err := getCustomEndpointUrlFromSnykApi(snykApiUrl, "app")
		if err != nil || snykUiUrl == "" {
			snykUiUrl = DefaultSnykUiUrl
		}
		conf.Set(configuration.WEB_APP_URL, snykUiUrl)
		return true
	}
	return false
}

// FolderOrganizationFromConfig returns the effective organization for a folder using the given configuration and logger.
func FolderOrganizationFromConfig(conf configuration.Configuration, folderPath types.FilePath, logger *zerolog.Logger) string {
	snapshot := types.ReadFolderConfigSnapshot(conf, folderPath)

	if snapshot.OrgSetByUser {
		if snapshot.PreferredOrg == "" {
			return conf.GetString(configuration.ORGANIZATION)
		}
		return snapshot.PreferredOrg
	}

	if snapshot.AutoDeterminedOrg == "" {
		globalOrg := conf.GetString(configuration.ORGANIZATION)
		logger.Trace().
			Str("method", "FolderOrganizationFromConfig").
			Str("globalOrg", globalOrg).
			Str("folderPath", string(folderPath)).
			Msg("AutoDeterminedOrg is empty, falling back to global organization")
		return globalOrg
	}
	return snapshot.AutoDeterminedOrg
}

type Config struct {
	scrubbingWriter          zerolog.LevelWriter
	logFile                  *os.File
	tokenChangeChannels      []chan string
	prepareDefaultEnvChannel chan bool
	engine                   workflow.Engine
	logger                   *zerolog.Logger
	storage                  storage.StorageWithCallbacks
	m                        sync.RWMutex
	ws                       types.Workspace
	ldxSyncConfigCache       types.LDXSyncConfigCache
	configResolver           types.ConfigResolverInterface
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

	c.logger = getNewScrubbingLogger(c)
	c.prepareDefaultEnvChannel = make(chan bool, 1)
	if engine == nil {
		initWorkFlowEngine(c)
	} else {
		// Engine is provided externally, e.g. we were invoked from CLI.
		c.engine = engine
	}

	engineConfig := c.engine.GetConfiguration()
	engineConfig.AddDefaultValue(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, configuration.ImmutableDefaultValueFunction(true))
	engineConfig.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	// Register all configuration flags so defaults are available via GAF
	fs := pflag.NewFlagSet("snyk-ls-defaults", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = engineConfig.AddFlagSet(fs)

	// Apply options after engine is ready so they can use GAF setters
	for _, opt := range opts {
		opt(c)
	}

	// Set non-zero boolean defaults on GAF Configuration
	engineConfig.Set(configuration.UserGlobalKey(types.SettingSnykOssEnabled), true)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingSnykIacEnabled), true)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingSendErrorReports), true)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingAutomaticDownload), true)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingAutomaticAuthentication), true)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingTrustEnabled), true)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingScanAutomatic), true)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingEnableSnykLearnCodeActions), true)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingAuthenticationMethod), string(types.TokenAuthentication))
	engineConfig.Set(configuration.UserGlobalKey(types.SettingToken), "")

	// Set other defaults via GAF
	engineConfig.Set(configuration.UserGlobalKey(types.SettingCliPath), "")
	if _, ok := engineConfig.Get(configuration.UserGlobalKey(types.SettingBinarySearchPaths)).([]string); !ok {
		engineConfig.Set(configuration.UserGlobalKey(types.SettingBinarySearchPaths), getDefaultBinarySearchPaths())
	}
	engineConfig.Set(configuration.UserGlobalKey(types.SettingConfigFile), "")
	engineConfig.Set("configfile", "")
	engineConfig.Set(configuration.UserGlobalKey(types.SettingFormat), FormatMd)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingSnykCodeAnalysisTimeout), SnykCodeAnalysisTimeoutFromEnv(c.logger))
	c.determineDeviceId()
	c.addDefaults()
	// Severity filter defaults
	df := types.DefaultSeverityFilter()
	engineConfig.Set(configuration.UserGlobalKey(types.SettingSeverityFilterCritical), df.Critical)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingSeverityFilterHigh), df.High)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingSeverityFilterMedium), df.Medium)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingSeverityFilterLow), df.Low)
	// Issue view defaults
	dio := types.DefaultIssueViewOptions()
	engineConfig.Set(configuration.UserGlobalKey(types.SettingIssueViewOpenIssues), dio.OpenIssues)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingIssueViewIgnoredIssues), dio.IgnoredIssues)
	UpdateApiEndpointsOnConfig(c.engine.GetConfiguration(), DefaultSnykApiUrl)
	c.clientSettingsFromEnv()
	c.engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingHoverVerbosity), 3)
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
	id, machineErr := machineid.ProtectedID("Snyk-LS")
	if machineErr != nil {
		c.Logger().Err(machineErr).Str("method", "config.New").Msg("cannot retrieve machine id")
		token := GetToken(c.engine.GetConfiguration())
		if token != "" {
			c.engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingDeviceId), util.Hash([]byte(token)))
			return util.Hash([]byte(token))
		}
		c.engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingDeviceId), uuid.NewString())
		return uuid.NewString()
	}
	c.engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingDeviceId), id)
	return id
}

// GetToken returns the authentication token from the given configuration.
// Checks configuration.UserGlobalKey(types.SettingToken) first, then AUTHENTICATION_TOKEN, then CONFIG_KEY_OAUTH_TOKEN.
func GetToken(conf configuration.Configuration) string {
	key := configuration.UserGlobalKey(types.SettingToken)
	if conf.IsSet(key) {
		return conf.GetString(key)
	}
	token := conf.GetString(configuration.AUTHENTICATION_TOKEN)
	if token == "" {
		token = conf.GetString(auth.CONFIG_KEY_OAUTH_TOKEN)
	}
	return token
}

// CliInstalled returns true if the CLI binary is installed at the path configured in conf.
func CliInstalled(conf configuration.Configuration) bool {
	cliPath := conf.GetString(configuration.UserGlobalKey(types.SettingCliPath))
	stat, err := cliPathFileInfo(cliPath)
	isDirectory := stat != nil && stat.IsDir()
	if isDirectory {
		log.Warn().Msgf("CLI path (%s) refers to a directory and not a file", cliPath)
	}
	return cliPath != "" && err == nil && !isDirectory
}

func cliPathFileInfo(cliPath string) (os.FileInfo, error) {
	stat, err := os.Stat(cliPath)
	if err == nil {
		log.Trace().Str("method", "config.cliPathFileInfo").Msgf("CLI path: %s, Size: %d, Perm: %s",
			cliPath,
			stat.Size(),
			stat.Mode().Perm())
	}
	return stat, err
}

// CliDefaultBinaryInstallPath returns the default directory for installing the Snyk CLI binary.
func CliDefaultBinaryInstallPath() string {
	lsPath := filepath.Join(xdg.DataHome, "snyk-ls")
	err := os.MkdirAll(lsPath, 0o755)
	if err != nil {
		log.Err(err).Str("method", "lsPath").Msgf("couldn't create %s", lsPath)
		return ""
	}
	return lsPath
}

// CLIDownloadLockFileName returns the path to the CLI download lock file.
// If cliPath is empty in conf, sets it to CliDefaultBinaryInstallPath() and persists.
func CLIDownloadLockFileName(conf configuration.Configuration) (string, error) {
	cliPath := conf.GetString(configuration.UserGlobalKey(types.SettingCliPath))
	if cliPath == "" {
		cliPath = CliDefaultBinaryInstallPath()
		conf.Set(configuration.UserGlobalKey(types.SettingCliPath), cliPath)
	}
	path := filepath.Dir(cliPath)
	err := os.MkdirAll(path, 0o755)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "snyk-cli-download.lock"), nil
}

// CLIDownloadLockFileNameWithConfig returns the CLI download lock file path using the Config's engine.
// Holds Config mutex for thread safety when mutating configuration.
func (c *Config) CLIDownloadLockFileName() (string, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return CLIDownloadLockFileName(c.engine.GetConfiguration())
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

func (c *Config) SetToken(newTokenString string) {
	c.m.Lock()
	defer c.m.Unlock()

	conf := c.engine.GetConfiguration()
	oldTokenString := WriteTokenToConfig(conf, GetAuthenticationMethodFromConfig(conf), newTokenString, c.logger)

	newOAuthToken, _ := getAsOauthToken(newTokenString, c.logger)
	if w, ok := c.scrubbingWriter.(frameworkLogging.ScrubbingLogWriter); ok {
		if newTokenString != "" {
			w.AddTerm(newTokenString, 0)
			if newOAuthToken != nil && newOAuthToken.AccessToken != "" {
				w.AddTerm(newOAuthToken.AccessToken, 0)
				w.AddTerm(newOAuthToken.RefreshToken, 0)
			}
		}
	}

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

func (c *Config) ConfigureLogging(server types.Server) {
	var logLevel zerolog.Level
	var err error

	logLevel, err = zerolog.ParseLevel(GetLogLevel())
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
	SetLogLevel(logLevel.String())

	levelWriter := logging.New(server)
	writers := []io.Writer{levelWriter}

	logPath := c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingLogPath))
	if logPath != "" {
		c.logFile, err = os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "couldn't open logfile")
		} else {
			_, _ = fmt.Fprintln(os.Stderr, fmt.Sprint("adding file logger to file ", logPath))
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
	logPath := c.engine.GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingLogPath))
	c.Logger().Info().Msgf("Disabling file logging to %v", logPath)
	c.engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingLogPath), "")
	if c.logFile != nil {
		_ = c.logFile.Close()
	}
}

func (c *Config) SetConfigFile(configFile string) {
	c.engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingConfigFile), configFile)
	c.engine.GetConfiguration().Set("configfile", configFile)
}

// GetCodeApiUrlFromCustomEndpoint returns the Code API URL from env, sastResponse, or derived from the API endpoint in conf.
func GetCodeApiUrlFromCustomEndpoint(conf configuration.Configuration, sastResponse *sast_contract.SastResponse, logger *zerolog.Logger) (string, error) {
	deeproxyEnvVarUrl := strings.Trim(os.Getenv(DeeproxyApiUrlKey), "/")
	if deeproxyEnvVarUrl != "" {
		logger.Debug().Str("deeproxyEnvVarUrl", deeproxyEnvVarUrl).Msg("using deeproxy env variable for code api url")
		return deeproxyEnvVarUrl, nil
	}

	if sastResponse != nil && sastResponse.SastEnabled && sastResponse.LocalCodeEngine.Enabled {
		return sastResponse.LocalCodeEngine.Url, nil
	}

	return getCustomEndpointUrlFromSnykApi(conf.GetString(configuration.UserGlobalKey(types.SettingApiEndpoint)), "deeproxy")
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

func (c *Config) SetOrganization(organization string) {
	c.m.Lock()
	defer c.m.Unlock()

	organization = strings.TrimSpace(organization)

	// Skip if we're setting the exact same value as before to prevent redundant API calls.
	// Prevents re-resolving a slug and re-resolving "" to the user's preferred default org in the web UI.
	lastSet := c.engine.GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingLastSetOrganization))
	if organization == lastSet {
		return
	}

	c.engine.GetConfiguration().Set(configuration.ORGANIZATION, organization)
	c.engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingLastSetOrganization), organization)
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
		c.engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingCachedOriginalPath), os.Getenv("PATH"))
	}()
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

func (c *Config) Logger() *zerolog.Logger {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.logger
}

// AuthenticationMethodMatchesCredentials returns true if the token matches the configured authentication method.
func AuthenticationMethodMatchesCredentials(token string, method types.AuthenticationMethod, logger *zerolog.Logger) bool {
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
		_, err := getAsOauthToken(token, logger)
		if err == nil {
			derivedMethod = types.OAuthAuthentication
		}
	}

	return method == derivedMethod
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

	// refresh token if in storage
	if GetToken(conf) == "" {
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

// FolderConfigForSubPath returns the folder config for the workspace folder containing the given path.
// The path parameter can be a subdirectory or file within a workspace folder.
// Returns an error if the workspace is nil or if no workspace folder contains the path.
func FolderConfigForSubPath(workspace types.Workspace, path types.FilePath, engine workflow.Engine, resolver types.ConfigResolverInterface, logger *zerolog.Logger) (*types.FolderConfig, error) {
	if workspace == nil {
		return nil, fmt.Errorf("workspace is nil, so cannot determine folder config for path: %s", path)
	}

	workspaceFolder := workspace.GetFolderContaining(path)
	if workspaceFolder == nil {
		return nil, fmt.Errorf("no workspace folder found for path: %s", path)
	}

	return GetFolderConfigFromEngine(engine, resolver, workspaceFolder.Path(), logger), nil
}

// FolderOrganization returns the organization configured for a given folder path. If no organization is configured for
// the folder, it returns the global organization (which if unset, configuration will return the default org).
func FolderOrganization(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger) string {
	ctxLogger := logger.With().Str("method", "FolderOrganization").Str("path", string(path)).Logger()
	if path == "" {
		globalOrg := conf.GetString(configuration.ORGANIZATION)
		ctxLogger.Warn().Str("globalOrg", globalOrg).Msg("called with empty path, falling back to global organization")
		return globalOrg
	}

	fc, err := storedconfig.GetFolderConfigWithOptions(conf, path, logger, storedconfig.GetFolderConfigOptions{
		CreateIfNotExist: false,
		ReadOnly:         true,
		EnrichFromGit:    false,
	})
	if err != nil {
		globalOrg := conf.GetString(configuration.ORGANIZATION)
		ctxLogger.Warn().Err(err).Str("globalOrg", globalOrg).Msg("error getting folder config, falling back to global organization")
		return globalOrg
	}

	fcConf := fc.Conf()
	if fcConf == nil {
		fcConf = conf
	}
	return FolderOrganizationFromConfig(fcConf, fc.FolderPath, logger)
}

// FolderOrganizationSlug returns the organization slug for the given folder path.
func FolderOrganizationSlug(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger) string {
	clonedConfig := conf.Clone()
	clonedConfig.Set(configuration.ORGANIZATION, FolderOrganization(conf, path, logger))
	return clonedConfig.GetString(configuration.ORGANIZATION_SLUG)
}

// FolderOrganizationForSubPath returns the organization for the workspace folder containing the given path.
// Returns an error if the workspace is nil, if no folder contains the path, or if no organization can be determined.
func FolderOrganizationForSubPath(workspace types.Workspace, conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger) (string, error) {
	if workspace == nil {
		return "", fmt.Errorf("workspace is nil, so cannot determine organization for path: %s", path)
	}

	workspaceFolder := workspace.GetFolderContaining(path)
	if workspaceFolder == nil {
		return "", fmt.Errorf("cannot determine organization, no workspace folder found for path: %s", path)
	}

	folderOrg := FolderOrganization(conf, workspaceFolder.Path(), logger)
	if folderOrg == "" {
		return "", fmt.Errorf("no organization was able to be determined for folder: %s", workspaceFolder.Path())
	}

	return folderOrg, nil
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
