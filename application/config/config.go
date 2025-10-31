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
	"net/http"
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
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	ignoreworkflow "github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"golang.org/x/oauth2"

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
	err := os.MkdirAll(lsPath, 0o755)
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
	binarySearchPaths                []string
	automaticAuthentication          bool
	tokenChangeChannels              []chan string
	prepareDefaultEnvChannel         chan bool
	filterSeverity                   types.SeverityFilter
	issueViewOptions                 types.IssueViewOptions
	trustedFolders                   []types.FilePath
	trustedFoldersFeatureEnabled     bool
	activateSnykCodeSecurity         bool
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
	mcpBaseURL                       *url.URL
	isLSPInitialized                 bool
	snykAgentFixEnabled              bool
	cachedOriginalPath               string
	globalOrganization               string // Deprecated: Only used for migration. Use folder-specific org instead.
	userSettingsPath                 string
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

	// Override GAF default org function to throw errors - this helps us identify if anything relies on it
	// TODO - This is a temporary thing, we will probably remove it later after testing.
	overrideGAFDefaultOrgFunction(c.engine, gafConfig)

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

	conf := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)

	conf.PersistInStorage(storedConfig.ConfigMainKey)
	conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
	c.engine = app.CreateAppEngineWithOptions(app.WithConfiguration(conf), app.WithZeroLogger(c.logger))

	err := initWorkflows(c)
	if err != nil {
		c.Logger().Err(err).Msg("unable to initialize workflows")
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

// overrideGAFDefaultOrgFunction overrides the GAF default org function to throw an error
// when called with no existing value or empty string. This helps us identify if anything in snyk-ls relies on the GAF default org resolution.
// If a value is already set (non-empty), we return it (we're not relying on default resolution in that case).
// TODO - This is a temporary thing, we will probably remove it later after testing.
// If the "temp_use_real_gaf_default_org_func" flag is set in the config, we call the real GAF default org function instead.
func overrideGAFDefaultOrgFunction(engine workflow.Engine, gafConfig configuration.Configuration) {
	errorThrowingDefaultOrgFunc := func(cfg configuration.Configuration, existingValue any) (any, error) {
		// Check if the flag is set to use the real GAF default org function
		if cfg.GetString("temp_use_real_gaf_default_org_func") == "1" {
			// Call the real GAF default org function logic manually
			client := engine.GetNetworkAccess().GetHttpClient()
			apiUrl := cfg.GetString(configuration.API_URL)
			orgId, err := getDefaultOrgIdFromAPI(apiUrl, client)
			if err != nil {
				return nil, fmt.Errorf("failed to get default org ID: %w", err)
			}
			return orgId, nil
		}

		// If a value is already set and non-empty, return it (we're not relying on default resolution, usually set by tests)
		if existingValue != nil {
			if str, ok := existingValue.(string); ok && str != "" {
				return str, nil
			}
		}
		// No value set or empty string - throw error to detect if we're relying on default resolution
		// Tests that want to use the fallback (user's preferred org from web UI) should explicitly set an org value
		return nil, errors.New("GAF default org function called - this should not happen in snyk-ls")
	}
	gafConfig.AddDefaultValue(configuration.ORGANIZATION, errorThrowingDefaultOrgFunc)
}

// getDefaultOrgIdFromAPI manually calls the Snyk API to get the user's default org ID
// This replicates the logic from GAF's internal API client when the flag is set
// TODO - Delete this.
func getDefaultOrgIdFromAPI(apiUrl string, client *http.Client) (string, error) {
	// Construct the /rest/self endpoint URL
	baseURL := strings.TrimSuffix(apiUrl, "/")
	endpoint := baseURL + "/rest/self"

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add version header if needed (GAF uses SNYK_DEFAULT_API_VERSION)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call /rest/self: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code from /rest/self: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse the response - matching GAF's contract.SelfResponse structure
	var selfResponse struct {
		Data struct {
			Attributes struct {
				DefaultOrgContext string `json:"default_org_context"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &selfResponse); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if selfResponse.Data.Attributes.DefaultOrgContext == "" {
		return "", fmt.Errorf("default_org_context not found in response")
	}

	return selfResponse.Data.Attributes.DefaultOrgContext, nil
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

func (c *Config) SnykCodeApi() string {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.snykCodeApiUrl
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
	c.logger.Debug().Str("method", "SetSeverityFilter").Interface("severityFilter", severityFilter).Msg("Setting severity filter:")
	c.filterSeverity = *severityFilter
	return filterModified
}

func (c *Config) SetIssueViewOptions(issueViewOptions *types.IssueViewOptions) bool {
	c.m.Lock()
	defer c.m.Unlock()
	if issueViewOptions == nil {
		return false
	}
	issueViewOptionsModified := c.issueViewOptions != *issueViewOptions
	c.logger.Debug().Str("method", "SetIssueViewOptions").Interface("issueViewOptions", issueViewOptions).Msg("Setting issue view options:")
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

// Organization returns the deprecated global organization.
//
// Deprecated: Use FolderOrganization(path) to get organization per folder.
// This should now only be used for migration only.
func (c *Config) Organization() string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.globalOrganization
}

// SetOrganization sets the deprecated global organization.
//
// Deprecated: Use folder-specific organization configuration instead.
// This should now only be used for migration only.
func (c *Config) SetOrganization(organization string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.globalOrganization = organization
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
	conf.PersistInStorage(storedConfig.ConfigMainKey)
	conf.PersistInStorage(auth.CONFIG_KEY_OAUTH_TOKEN)
	conf.PersistInStorage(configuration.AUTHENTICATION_TOKEN)

	// now refresh from storage
	err := s.Refresh(conf, storedConfig.ConfigMainKey)
	if err != nil {
		c.logger.Err(err).Msg("unable to load stored config")
	}

	sc, err := storedConfig.GetStoredConfig(conf, c.logger)
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

func (c *Config) FolderConfig(path types.FilePath) *types.FolderConfig {
	var folderConfig *types.FolderConfig
	var err error
	folderConfig, err = storedConfig.GetOrCreateFolderConfig(c.engine.GetConfiguration(), path, c.Logger())
	if err != nil {
		folderConfig = &types.FolderConfig{FolderPath: path}
	}
	return folderConfig
}

func (c *Config) UpdateFolderConfig(folderConfig *types.FolderConfig) error {
	return storedConfig.UpdateFolderConfig(c.engine.GetConfiguration(), folderConfig, c.logger)
}

// FolderOrganization returns the organization configured for a given folder path. If no organization is configured for
// the folder, it gets the organization from the GAF config, which we should not have manually set,
// so should be defaulted to the user's preferred org from the web UI.
func (c *Config) FolderOrganization(path types.FilePath) string {
	fc := c.FolderConfig(path)
	clonedGAFConfig := c.engine.GetConfiguration().Clone()
	clonedGAFConfig.Set("temp_use_real_gaf_default_org_func", "1")
	if fc == nil {
		// Should never happen, but as a safety net, fall back to the user's preferred org from the web UI.
		return clonedGAFConfig.GetString(configuration.ORGANIZATION)
	}
	if fc.OrgSetByUser {
		if fc.PreferredOrg == "" {
			// If empty it is an indication that the user wants to use their preferred org from the web UI.
			return clonedGAFConfig.GetString(configuration.ORGANIZATION)
		} else {
			return fc.PreferredOrg
		}
	} else {
		// If AutoDeterminedOrg is empty, fall back to the user's preferred org from the web UI.
		if fc.AutoDeterminedOrg == "" {
			return clonedGAFConfig.GetString(configuration.ORGANIZATION)
		}
		return fc.AutoDeterminedOrg
	}
}

func (c *Config) FolderOrganizationSlug(path types.FilePath) string {
	folderOrg := c.FolderOrganization(path)
	if folderOrg == "" {
		// If folder org is empty, then we are probably not logged in, so we shall return early.
		return ""
	}
	clonedConfig := c.Engine().GetConfiguration()
	clonedConfig.Set(configuration.ORGANIZATION, folderOrg)
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

func (c *Config) SetMCPServerURL(baseURL *url.URL) {
	c.m.Lock()
	defer c.m.Unlock()
	c.mcpBaseURL = baseURL
}

func (c *Config) GetMCPServerURL() *url.URL {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.mcpBaseURL
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

func (c *Config) SetSnykAgentFixEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()

	c.snykAgentFixEnabled = enabled
}

func (c *Config) IsSnykAgentFixEnabled() bool {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.snykAgentFixEnabled
}

func (c *Config) EmptyToken() bool {
	return !c.NonEmptyToken()
}
