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
	"fmt"
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
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/subosito/gotenv"
	"github.com/xtgo/uuid"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/infrastructure/cli/filename"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	deeproxyApiUrlKey     = "DEEPROXY_API_URL"
	FormatHtml            = "html"
	FormatMd              = "md"
	snykCodeTimeoutKey    = "SNYK_CODE_TIMEOUT" // timeout as duration (number + unit), e.g. 10m
	defaultSnykApiUrl     = "https://snyk.io/api"
	defaultDeeproxyApiUrl = "https://deeproxy.snyk.io"
	pathListSeparator     = string(os.PathListSeparator)
	windows               = "windows"
	govDomain             = "snykgov.io"
)

var (
	Version            = "SNAPSHOT"
	LsProtocolVersion  = "development"
	Development        = "true"
	currentConfig      *Config
	mutex              = &sync.Mutex{}
	LicenseInformation = "License information\n FILLED DURING BUILD"
)

type CliSettings struct {
	Insecure                bool
	AdditionalOssParameters []string
	cliPath                 string
	cliPathAccessMutex      sync.Mutex
}

func NewCliSettings() *CliSettings {
	settings := &CliSettings{}
	settings.SetPath("")
	return settings
}

func (c *CliSettings) Installed() bool {
	c.cliPathAccessMutex.Lock()
	defer c.cliPathAccessMutex.Unlock()
	stat, err := os.Stat(c.cliPath)
	if err == nil {
		log.Debug().Str("method", "config.cliSettings.Installed").Msgf("CLI path: %s, Size: %d, Perm: %s", c.cliPath, stat.Size(), stat.Mode().Perm())
	}
	isDirectory := stat != nil && stat.IsDir()
	if isDirectory {
		log.Warn().Msgf("CLI path (%s) refers to a directory and not a file", c.cliPath)
	}
	return c.cliPath != "" && err == nil && !isDirectory
}

func (c *CliSettings) IsPathDefined() bool {
	c.cliPathAccessMutex.Lock()
	defer c.cliPathAccessMutex.Unlock()
	return c.cliPath != ""
}

// Path returns the full path to the CLI executable that is stored in the CLI configuration
func (c *CliSettings) Path() string {
	c.cliPathAccessMutex.Lock()
	defer c.cliPathAccessMutex.Unlock()
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
		log.Err(err).Str("method", "lsPath").Msgf("couldn't create %s", lsPath)
		return ""
	}
	return lsPath
}

type Config struct {
	configLoaded                 concurrency.AtomicBool
	cliSettings                  *CliSettings
	configFile                   string
	format                       string
	isErrorReportingEnabled      concurrency.AtomicBool
	isSnykCodeEnabled            concurrency.AtomicBool
	isSnykOssEnabled             concurrency.AtomicBool
	isSnykIacEnabled             concurrency.AtomicBool
	isSnykContainerEnabled       concurrency.AtomicBool
	isSnykAdvisorEnabled         concurrency.AtomicBool
	isTelemetryEnabled           concurrency.AtomicBool
	manageBinariesAutomatically  concurrency.AtomicBool
	logPath                      string
	logFile                      *os.File
	organization                 string
	snykCodeAnalysisTimeout      time.Duration
	snykApiUrl                   string
	snykCodeApiUrl               string
	token                        string
	deviceId                     string
	clientCapabilities           sglsp.ClientCapabilities
	m                            sync.Mutex
	path                         string
	defaultDirs                  []string
	integrationName              string
	integrationVersion           string
	automaticAuthentication      bool
	tokenChangeChannels          []chan string
	filterSeverity               lsp.SeverityFilter
	trustedFolders               []string
	trustedFoldersFeatureEnabled bool
	activateSnykCodeSecurity     bool
	activateSnykCodeQuality      bool
	osPlatform                   string
	osArch                       string
	runtimeName                  string
	runtimeVersion               string
	automaticScanning            bool
	authenticationMethod         lsp.AuthenticationMethod
	isSnykAutofixEnabled         concurrency.AtomicBool
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

// New creates a configuration object with default values
func New() *Config {
	c := &Config{}
	c.cliSettings = NewCliSettings()
	c.automaticAuthentication = true
	c.configFile = ""
	c.format = "md"
	c.isErrorReportingEnabled.Set(true)
	c.isTelemetryEnabled.Set(true)
	c.isSnykOssEnabled.Set(true)
	c.isSnykIacEnabled.Set(true)
	c.manageBinariesAutomatically.Set(true)
	c.logPath = ""
	c.snykApiUrl = defaultSnykApiUrl
	c.snykCodeApiUrl = defaultDeeproxyApiUrl
	c.snykCodeAnalysisTimeout = snykCodeAnalysisTimeoutFromEnv()
	c.token = ""
	c.trustedFoldersFeatureEnabled = true
	c.automaticScanning = true
	c.authenticationMethod = lsp.TokenAuthentication
	c.clientSettingsFromEnv()
	c.deviceId = c.determineDeviceId()
	c.addDefaults()
	c.filterSeverity = lsp.DefaultSeverityFilter()
	c.isSnykAutofixEnabled.Set(false)
	return c
}

func (c *Config) AddBinaryLocationsToPath(searchDirectories []string) {
	c.defaultDirs = searchDirectories
	c.determineJavaHome()
	c.determineMavenHome()
}

func (c *Config) determineDeviceId() string {
	id, machineErr := machineid.ProtectedID("Snyk-LS")
	if machineErr != nil {
		log.Err(machineErr).Str("method", "config.New").Msg("cannot retrieve machine id")
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
	return c.trustedFoldersFeatureEnabled
}

func (c *Config) SetTrustedFolderFeatureEnabled(enabled bool) {
	c.m.Lock()
	defer c.m.Unlock()
	c.trustedFoldersFeatureEnabled = enabled
}

func (c *Config) Load() {
	files := c.configFiles()
	for _, fileName := range files {
		c.loadFile(fileName)
	}

	c.configLoaded.Set(true)
}

func (c *Config) loadFile(fileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Info().Str("method", "loadFile").Msg("Couldn't load " + fileName)
		return
	}
	defer func(file *os.File) { _ = file.Close() }(file)
	env := gotenv.Parse(file)
	for k, v := range env {
		_, exists := os.LookupEnv(k)
		if !exists {
			err := os.Setenv(k, v)
			if err != nil {
				log.Warn().Str("method", "loadFile").Msg("Couldn't set environment variable " + k)
			}
		} else {
			// add to path, don't ignore additional paths
			if k == "PATH" {
				c.updatePath(v)
			}
		}
	}
	c.updatePath(".")
	log.Debug().Str("fileName", fileName).Msg("loaded.")
}

func (c *Config) NonEmptyToken() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.token != ""
}
func (c *Config) CliSettings() *CliSettings {
	c.m.Lock()
	defer c.m.Unlock()
	return c.cliSettings
}

func (c *Config) Format() string { return c.format }
func (c *Config) CLIDownloadLockFileName() string {
	return filepath.Join(c.cliSettings.DefaultBinaryInstallPath(), "snyk-cli-download.lock")
}
func (c *Config) IsErrorReportingEnabled() bool          { return c.isErrorReportingEnabled.Get() }
func (c *Config) IsSnykOssEnabled() bool                 { return c.isSnykOssEnabled.Get() }
func (c *Config) IsSnykCodeEnabled() bool                { return c.isSnykCodeEnabled.Get() }
func (c *Config) IsSnykIacEnabled() bool                 { return c.isSnykIacEnabled.Get() }
func (c *Config) IsSnykContainerEnabled() bool           { return c.isSnykContainerEnabled.Get() }
func (c *Config) IsSnykAdvisorEnabled() bool             { return c.isSnykAdvisorEnabled.Get() }
func (c *Config) IsSnykAutofixEnabled() bool             { return c.isSnykAutofixEnabled.Get() }
func (c *Config) LogPath() string                        { return c.logPath }
func (c *Config) SnykApi() string                        { return c.snykApiUrl }
func (c *Config) SnykCodeApi() string                    { return c.snykCodeApiUrl }
func (c *Config) SnykCodeAnalysisTimeout() time.Duration { return c.snykCodeAnalysisTimeout }
func (c *Config) IntegrationName() string                { return c.integrationName }
func (c *Config) IntegrationVersion() string             { return c.integrationVersion }
func (c *Config) FilterSeverity() lsp.SeverityFilter     { return c.filterSeverity }
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
		snykApiUrl = defaultSnykApiUrl
	}

	if strings.Contains(snykApiUrl, govDomain) {
		c.authenticationMethod = "oauth"
	}

	if snykApiUrl != c.snykApiUrl {
		c.snykApiUrl = snykApiUrl

		// Update Code API endpoint
		snykCodeApiUrl, err := getCodeApiUrlFromCustomEndpoint(snykApiUrl)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't obtain Snyk Code API url from CLI endpoint.")
		}

		c.setSnykCodeApi(snykCodeApiUrl)
		return true
	}
	return false
}

func (c *Config) setSnykCodeApi(snykCodeApiUrl string) {
	if snykCodeApiUrl == "" {
		c.snykCodeApiUrl = defaultDeeproxyApiUrl
		return
	}
	c.snykCodeApiUrl = snykCodeApiUrl
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

func (c *Config) SetSnykAutofixEnabled(enabled bool) { c.isSnykAutofixEnabled.Set(enabled) }

func (c *Config) SetSeverityFilter(severityFilter lsp.SeverityFilter) bool {
	emptySeverityFilter := lsp.SeverityFilter{}
	if severityFilter == emptySeverityFilter {
		return false
	}

	filterModified := c.filterSeverity != severityFilter
	log.Debug().Str("method", "SetSeverityFilter").Msgf("Setting severity filter: %v", severityFilter)
	c.filterSeverity = severityFilter
	return filterModified
}

func (c *Config) SetToken(token string) {
	c.m.Lock()
	defer c.m.Unlock()
	if token == c.token { // No need to do anything if the token hasn't changed
		return
	}

	// Notify that the token has changed
	for _, channel := range c.tokenChangeChannels {
		select {
		case channel <- token:
		default:
			// Using select and a default case avoids deadlock when the channel is full
			log.Warn().Msg("Cannot send cancellation token to channel - channel is full")
		}
	}
	c.tokenChangeChannels = []chan string{}

	c.token = token
}
func (c *Config) SetFormat(format string) { c.format = format }

func (c *Config) SetLogPath(logPath string) {
	c.logPath = logPath
}

func (c *Config) ConfigureLogging(level string) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		fmt.Println("Can't set log level from flag. Setting to default (=info)")
		logLevel = zerolog.InfoLevel
	}

	// env var overrides flag
	envLogLevel := os.Getenv("SNYK_LOG_LEVEL")
	if envLogLevel != "" {
		fmt.Println("Setting log level from environment variable (SNYK_LOG_LEVEL)", envLogLevel)
		envLevel, err := zerolog.ParseLevel(envLogLevel)
		if err != nil {
			fmt.Println("Can't set log level from env. Setting to default (=info)")
			// fallback to flag
			envLevel = logLevel
		}
		logLevel = envLevel
	}
	zerolog.SetGlobalLevel(logLevel)
	zerolog.TimeFieldFormat = time.RFC3339

	if c.logPath != "" {
		c.logFile, err = os.OpenFile(c.logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Err(err).Msg("couldn't open logfile")
		}
		log.Info().Msgf("Logging to file %s", c.logPath)
		log.Logger = log.Output(c.logFile)
	} else {
		log.Info().Msgf("Logging to console") // TODO: log using LSP's 'window/logMessage'
		log.Logger = zerolog.New(os.Stderr)
	}
}

// DisableLoggingToFile closes the open log file and sets the global logger back to it's default
func (c *Config) DisableLoggingToFile() {
	log.Info().Msgf("Disabling file logging to %v", c.logPath)
	c.logPath = ""
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
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
		return defaultDeeproxyApiUrl, nil
	}

	// Use Snyk API endpoint to determine deeproxy API URL
	endpointUrl, err := url.Parse(strings.Trim(endpoint, " "))
	if err != nil {
		return "", err
	}

	m := regexp.MustCompile(`^(ap[pi]\.)?`)
	endpointUrl.Host = m.ReplaceAllString(endpointUrl.Host, "deeproxy.")
	endpointUrl.Path = ""

	return endpointUrl.String(), nil
}

func snykCodeAnalysisTimeoutFromEnv() time.Duration {
	var snykCodeTimeout time.Duration
	var err error
	env := os.Getenv(snykCodeTimeoutKey)
	if env == "" {
		snykCodeTimeout = 10 * time.Minute
	} else {
		snykCodeTimeout, err = time.ParseDuration(env)
		if err != nil {
			log.Err(err).Msg("couldn't convert timeout env variable to integer")
		}
	}
	return snykCodeTimeout
}

func (c *Config) updatePath(pathExtension string) {
	if pathExtension == "" {
		return
	}
	err := os.Setenv("PATH", os.Getenv("PATH")+pathListSeparator+pathExtension)
	c.path += pathListSeparator + pathExtension
	log.Debug().Str("method", "updatePath").Msg("updated path with " + pathExtension)
	if err != nil {
		log.Warn().Str("method", "loadFile").Msg("Couldn't update path ")
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
	stdFiles := []string{
		".snyk.env",
		home + "/.snyk.env",
	}
	return append(files, stdFiles...)
}

func (c *Config) GetOrganization() string {
	return c.organization
}

func (c *Config) SetOrganization(organization string) {
	c.organization = organization
}

func (c *Config) ManageBinariesAutomatically() bool {
	return c.manageBinariesAutomatically.Get()
}

func (c *Config) SetManageBinariesAutomatically(enabled bool) {
	c.manageBinariesAutomatically.Set(enabled)
}

func (c *Config) IsTelemetryEnabled() bool {
	return c.isTelemetryEnabled.Get()
}

func (c *Config) SetTelemetryEnabled(enabled bool) {
	c.isTelemetryEnabled.Set(enabled)
}

func (c *Config) telemetryEnablementFromEnv() {
	value := os.Getenv(EnableTelemetry)
	if value == "1" {
		c.isTelemetryEnabled.Set(false)
	} else {
		c.isTelemetryEnabled.Set(true)
	}
}

func (c *Config) DeviceID() string {
	return c.deviceId
}

func (c *Config) SetDeviceID(deviceId string) {
	c.deviceId = deviceId
}

func (c *Config) ClientCapabilities() sglsp.ClientCapabilities {
	return c.clientCapabilities
}

func (c *Config) SetClientCapabilities(capabilities sglsp.ClientCapabilities) {
	c.clientCapabilities = capabilities
}

func (c *Config) Path() string {
	return c.path
}

func (c *Config) AutomaticAuthentication() bool {
	return c.automaticAuthentication
}

func (c *Config) SetAutomaticAuthentication(value bool) {
	c.automaticAuthentication = value
}

func (c *Config) SetAutomaticScanning(value bool) {
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
	c.determineMavenHome()
}

func (c *Config) SetIntegrationName(integrationName string) {
	c.integrationName = integrationName
}

func (c *Config) SetIntegrationVersion(integrationVersion string) {
	c.integrationVersion = integrationVersion
}

func (c *Config) TrustedFolders() []string {
	c.m.Lock()
	defer c.m.Unlock()
	return c.trustedFolders
}

func (c *Config) SetTrustedFolders(folderPaths []string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.trustedFolders = folderPaths
}

func (c *Config) GetDisplayableIssueTypes() map[product.FilterableIssueType]bool {
	enabled := make(map[product.FilterableIssueType]bool)
	enabled[product.FilterableIssueTypeOpenSource] = c.IsSnykOssEnabled()

	// Handle backwards compatibility.
	// Older configurations had a single value for both snyk code issue types (security & quality)
	// New configurations have 1 for each, and should ignore the general IsSnykCodeEnabled value.
	enabled[product.FilterableIssueTypeCodeSecurity] = c.IsSnykCodeEnabled() || c.IsSnykCodeSecurityEnabled()
	enabled[product.FilterableIssueTypeCodeQuality] = c.IsSnykCodeEnabled() || c.IsSnykCodeQualityEnabled()

	enabled[product.FilterableIssueTypeInfrastructureAsCode] = c.IsSnykIacEnabled()

	return enabled
}

func (c *Config) IsSnykCodeSecurityEnabled() bool {
	return c.activateSnykCodeSecurity
}

func (c *Config) EnableSnykCodeSecurity(activate bool) {
	c.activateSnykCodeSecurity = activate
}

func (c *Config) IsSnykCodeQualityEnabled() bool {
	return c.activateSnykCodeQuality
}

func (c *Config) EnableSnykCodeQuality(activate bool) {
	c.activateSnykCodeQuality = activate
}

func (c *Config) OsPlatform() string {
	return c.osPlatform
}

func (c *Config) SetOsPlatform(osPlatform string) {
	c.osPlatform = osPlatform
}

func (c *Config) OsArch() string {
	return c.osArch
}

func (c *Config) SetOsArch(osArch string) {
	c.osArch = osArch
}

func (c *Config) RuntimeName() string {
	return c.runtimeName
}

func (c *Config) SetRuntimeName(runtimeName string) {
	c.runtimeName = runtimeName
}

func (c *Config) RuntimeVersion() string {
	return c.runtimeVersion
}

func (c *Config) SetRuntimeVersion(runtimeVersion string) {
	c.runtimeVersion = runtimeVersion
}

func (c *Config) IsAutoScanEnabled() bool {
	return c.automaticScanning
}

func (c *Config) SetAuthenticationMethod(method lsp.AuthenticationMethod) {
	c.authenticationMethod = method
}

func (c *Config) GetAuthenticationMethod() lsp.AuthenticationMethod {
	return c.authenticationMethod
}
