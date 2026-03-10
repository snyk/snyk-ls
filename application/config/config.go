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
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/envvars"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	ignoreworkflow "github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/pkg/osflows"

	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/logging"
	"github.com/snyk/snyk-ls/internal/storage"
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
	LicenseInformation             = "License information\n FILLED DURING BUILD"
	analyticsPermittedEnvironments = map[string]bool{
		"api.snyk.io":    true,
		"api.us.snyk.io": true,
	}
	loggingMu      sync.Mutex
	currentLogFile *os.File
)

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
	return types.AuthenticationMethod(conf.GetString(configresolver.UserGlobalKey(types.SettingAuthenticationMethod)))
}

// ManageCliBinariesAutomatically returns true if CLI binaries should be managed automatically (standalone mode + setting enabled).
func ManageCliBinariesAutomatically(conf configuration.Configuration) bool {
	if conf.GetString(cli_constants.EXECUTION_MODE_KEY) != cli_constants.EXECUTION_MODE_VALUE_STANDALONE {
		return false
	}
	return conf.GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload))
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
	snykApiUrl := conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint))
	snykUiUrl, err := getCustomEndpointUrlFromSnykApi(snykApiUrl, "app")
	if err != nil || snykUiUrl == "" {
		return DefaultSnykUiUrl
	}
	return snykUiUrl
}

// GetSnykCodeAnalysisTimeout returns the Snyk Code analysis timeout from the given configuration.
func GetSnykCodeAnalysisTimeout(conf configuration.Configuration) time.Duration {
	if v, ok := conf.Get(configresolver.UserGlobalKey(types.SettingSnykCodeAnalysisTimeout)).(time.Duration); ok {
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
	folderConfig, err := folderconfig.GetOrCreateFolderConfig(conf, path, logger)
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
	folderConfig, err := folderconfig.GetFolderConfigWithOptions(conf, path, logger, folderconfig.GetFolderConfigOptions{
		CreateIfNotExist: true,
		ReadOnly:         true,
		EnrichFromGit:    false,
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
		fc.ConfigResolver = types.NewMinimalConfigResolver(engine.GetConfiguration())
	}
}

// WriteTokenToConfig writes a token string to the GAF configuration, handling OAuth vs legacy token placement.
// Returns the old token string for comparison by callers that need change detection.
func WriteTokenToConfig(conf configuration.Configuration, authMethod types.AuthenticationMethod, newTokenString string, logger *zerolog.Logger) string {
	key := configresolver.UserGlobalKey(types.SettingToken)
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

	conf.Set(configresolver.UserGlobalKey(types.SettingToken), newTokenString)

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
	current := conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint))
	if snykApiUrl != current {
		conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), snykApiUrl)
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
			return types.GetGlobalOrganization(conf)
		}
		return snapshot.PreferredOrg
	}

	if snapshot.AutoDeterminedOrg == "" {
		globalOrg := types.GetGlobalOrganization(conf)
		logger.Trace().
			Str("method", "FolderOrganizationFromConfig").
			Str("globalOrg", globalOrg).
			Str("folderPath", string(folderPath)).
			Msg("AutoDeterminedOrg is empty, falling back to global organization")
		return globalOrg
	}
	return snapshot.AutoDeterminedOrg
}

func IsDevelopment() bool {
	parseBool, _ := strconv.ParseBool(Development)
	return parseBool
}

// InitEngine creates a standalone workflow engine with all workflows registered and initialized.
// Returns the engine and a TokenServiceImpl. For extension mode, pass the engine from the CLI.
func InitEngine(engine workflow.Engine) (workflow.Engine, *TokenServiceImpl) {
	sw := frameworkLogging.NewScrubbingWriter(logging.New(nil), make(frameworkLogging.ScrubbingDict))
	writer := newConsoleWriter(sw)
	logger := zerolog.New(writer).With().Timestamp().Str("separator", "-").Str("method", "").Str("ext", "").Logger()

	ts := &TokenServiceImpl{
		scrubbingWriter: sw,
		logger:          &logger,
	}

	if engine == nil {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		conf.PersistInStorage(folderconfig.ConfigMainKey)
		conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
		engine = app.CreateAppEngineWithOptions(app.WithConfiguration(conf), app.WithZeroLogger(&logger))

		if err := InitWorkflows(engine); err != nil {
			log.Err(err).Msg("unable to initialize workflows")
		}

		if err := engine.Init(); err != nil {
			logger.Warn().Err(err).Msg("unable to initialize workflow engine")
		}

		if engine.GetRuntimeInfo() == nil {
			rti := runtimeinfo.New(runtimeinfo.WithName("snyk-ls"), runtimeinfo.WithVersion(Version))
			engine.SetRuntimeInfo(rti)
		}
	}

	SetEngineDefaults(engine, &logger)
	StartEnvDefaults(engine, &logger)

	return engine, ts
}

// InitWorkflows registers all workflow extensions on the engine.
func InitWorkflows(engine workflow.Engine) error {
	if err := localworkflows.InitWhoAmIWorkflow(engine); err != nil {
		return err
	}
	if err := ignoreworkflow.InitIgnoreWorkflows(engine); err != nil {
		return err
	}
	if err := code.Init(engine); err != nil {
		return err
	}
	if err := osflows.Init(engine); err != nil {
		return err
	}
	if err := secrets.Init(engine); err != nil {
		return err
	}
	return nil
}

// SetEngineDefaults registers all configuration flags and sets default values on the engine's configuration.
func SetEngineDefaults(engine workflow.Engine, logger *zerolog.Logger) {
	engineConfig := engine.GetConfiguration()
	engineConfig.AddDefaultValue(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, configuration.ImmutableDefaultValueFunction(true))
	engineConfig.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	fs := pflag.NewFlagSet("snyk-ls-defaults", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = engineConfig.AddFlagSet(fs)

	engineConfig.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), true)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), true)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), true)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingEnableSnykLearnCodeActions), true)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.TokenAuthentication))
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingToken), "")
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingCliPath), "")
	if _, ok := engineConfig.Get(configresolver.UserGlobalKey(types.SettingBinarySearchPaths)).([]string); !ok {
		engineConfig.Set(configresolver.UserGlobalKey(types.SettingBinarySearchPaths), getDefaultBinarySearchPaths())
	}
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingConfigFile), "")
	engineConfig.Set(types.SettingConfigFileLegacy, "")
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingFormat), FormatMd)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingSnykCodeAnalysisTimeout), SnykCodeAnalysisTimeoutFromEnv(logger))
	DetermineDeviceId(engineConfig, logger)

	df := types.DefaultSeverityFilter()
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterCritical), df.Critical)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterHigh), df.High)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterMedium), df.Medium)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterLow), df.Low)

	dio := types.DefaultIssueViewOptions()
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingIssueViewOpenIssues), dio.OpenIssues)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingIssueViewIgnoredIssues), dio.IgnoredIssues)
	UpdateApiEndpointsOnConfig(engineConfig, DefaultSnykApiUrl)
	ClientSettingsFromEnv(engineConfig, logger)
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingHoverVerbosity), 3)
}

// StartEnvDefaults launches a goroutine that prepares the default environment (PATH, JAVA_HOME, Maven).
func StartEnvDefaults(engine workflow.Engine, logger *zerolog.Logger) {
	conf := engine.GetConfiguration()
	readyCh := types.NewDefaultEnvReadyChannel(conf)
	go func() {
		defer close(readyCh)
		//goland:noinspection GoBoolExpressions
		if runtime.GOOS != "windows" {
			envvars.UpdatePath("/usr/local/bin", false)
			envvars.UpdatePath("/bin", false)
			envvars.UpdatePath(xdg.Home+"/bin", false)
		}
		DetermineJavaHome(conf, logger)
		MavenDefaults(conf, logger)
		conf.Set(configresolver.UserGlobalKey(types.SettingCachedOriginalPath), os.Getenv("PATH"))
	}()
}

// DetermineDeviceId determines a unique device ID and stores it in configuration.
func DetermineDeviceId(conf configuration.Configuration, logger *zerolog.Logger) string {
	id, machineErr := machineid.ProtectedID("Snyk-LS")
	if machineErr != nil {
		logger.Err(machineErr).Str("method", "config.DetermineDeviceId").Msg("cannot retrieve machine id")
		token := GetToken(conf)
		if token != "" {
			conf.Set(configresolver.UserGlobalKey(types.SettingDeviceId), util.Hash([]byte(token)))
			return util.Hash([]byte(token))
		}
		conf.Set(configresolver.UserGlobalKey(types.SettingDeviceId), uuid.NewString())
		return uuid.NewString()
	}
	conf.Set(configresolver.UserGlobalKey(types.SettingDeviceId), id)
	return id
}

// GetToken returns the authentication token from the given configuration.
func GetToken(conf configuration.Configuration) string {
	key := configresolver.UserGlobalKey(types.SettingToken)
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
	cliPath := conf.GetString(configresolver.UserGlobalKey(types.SettingCliPath))
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
func CLIDownloadLockFileName(conf configuration.Configuration) (string, error) {
	cliPath := conf.GetString(configresolver.UserGlobalKey(types.SettingCliPath))
	if cliPath == "" {
		cliPath = CliDefaultBinaryInstallPath()
		conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)
	}
	path := filepath.Dir(cliPath)
	err := os.MkdirAll(path, 0o755)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "snyk-cli-download.lock"), nil
}

// SetupLogging configures the logger on the engine and token service, setting
// up scrubbing and optional file logging.
func SetupLogging(engine workflow.Engine, ts *TokenServiceImpl, server types.Server) {
	var logLevel zerolog.Level
	var err error

	logLevel, err = zerolog.ParseLevel(GetLogLevel())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Can't set log level from flag. Setting to default (=info)")
		logLevel = zerolog.InfoLevel
	}

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

	logPath := engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingLogPath))
	if logPath != "" {
		lf, openErr := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if openErr != nil {
			_, _ = fmt.Fprintln(os.Stderr, "couldn't open logfile")
		} else {
			_, _ = fmt.Fprintln(os.Stderr, fmt.Sprint("adding file logger to file ", logPath))
			writers = append(writers, lf)
			loggingMu.Lock()
			currentLogFile = lf
			loggingMu.Unlock()
		}
	}

	sw := frameworkLogging.NewScrubbingWriter(zerolog.MultiLevelWriter(writers...), make(frameworkLogging.ScrubbingDict))

	writer := newConsoleWriter(sw)
	logger := zerolog.New(writer).With().Timestamp().Str("separator", "-").Str("method", "").Str("ext", "").Logger().Level(logLevel)
	engine.SetLogger(&logger)
	ts.SetScrubbingWriter(sw)
	ts.SetLogger(&logger)
}

func newConsoleWriter(writer io.Writer) zerolog.ConsoleWriter {
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

// DisableFileLogging closes the current log file and clears the log path setting.
func DisableFileLogging(conf configuration.Configuration, logger *zerolog.Logger) {
	logPath := conf.GetString(configresolver.UserGlobalKey(types.SettingLogPath))
	logger.Info().Msgf("Disabling file logging to %v", logPath)
	conf.Set(configresolver.UserGlobalKey(types.SettingLogPath), "")
	loggingMu.Lock()
	defer loggingMu.Unlock()
	if currentLogFile != nil {
		_ = currentLogFile.Close()
		currentLogFile = nil
	}
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

	return getCustomEndpointUrlFromSnykApi(conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)), "deeproxy")
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

// SetOrganization sets the organization on the given GAF configuration.
func SetOrganization(conf configuration.Configuration, organization string) {
	organization = strings.TrimSpace(organization)

	lastSet := conf.GetString(configresolver.UserGlobalKey(types.SettingLastSetOrganization))
	if organization == lastSet {
		return
	}

	conf.Set(configuration.ORGANIZATION, organization)
	conf.Set(configresolver.UserGlobalKey(types.SettingLastSetOrganization), organization)
}

// AuthenticationMethodMatchesCredentials returns true if the token matches the configured authentication method.
func AuthenticationMethodMatchesCredentials(token string, method types.AuthenticationMethod, logger *zerolog.Logger) bool {
	if method == types.FakeAuthentication {
		return true
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

func SetupStorage(conf configuration.Configuration, s storage.StorageWithCallbacks, logger *zerolog.Logger) {
	conf.SetStorage(s)
	conf.PersistInStorage(folderconfig.ConfigMainKey)
	conf.PersistInStorage(auth.CONFIG_KEY_OAUTH_TOKEN)
	conf.PersistInStorage(configuration.AUTHENTICATION_TOKEN)

	err := s.Refresh(conf, folderconfig.ConfigMainKey)
	if err != nil {
		logger.Err(err).Msg("unable to load stored config")
	}

	if GetToken(conf) == "" {
		err = s.Refresh(conf, auth.CONFIG_KEY_OAUTH_TOKEN)
		if err != nil {
			logger.Err(err).Msg("unable to refresh storage")
		}
		err = s.Refresh(conf, configuration.AUTHENTICATION_TOKEN)
		if err != nil {
			logger.Err(err).Msg("unable to refresh storage")
		}
	}
}

// FolderConfigForSubPath returns the folder config for the workspace folder containing the given path.
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

// FolderOrganization returns the organization configured for a given folder path.
func FolderOrganization(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger) string {
	ctxLogger := logger.With().Str("method", "FolderOrganization").Str("path", string(path)).Logger()
	if path == "" {
		globalOrg := types.GetGlobalOrganization(conf)
		ctxLogger.Warn().Str("globalOrg", globalOrg).Msg("called with empty path, falling back to global organization")
		return globalOrg
	}

	fc, err := folderconfig.GetFolderConfigWithOptions(conf, path, logger, folderconfig.GetFolderConfigOptions{
		CreateIfNotExist: false,
		ReadOnly:         true,
		EnrichFromGit:    false,
	})
	if err != nil {
		globalOrg := types.GetGlobalOrganization(conf)
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

func GetWorkspace(conf configuration.Configuration) types.Workspace {
	w, _ := conf.Get(types.SettingWorkspace).(types.Workspace)
	return w
}

func SetWorkspace(conf configuration.Configuration, w types.Workspace) {
	conf.Set(types.SettingWorkspace, w)
}
