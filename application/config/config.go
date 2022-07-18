package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/subosito/gotenv"

	"github.com/snyk/snyk-ls/internal/concurrency"
)

const (
	SnykTokenKey          = "SNYK_TOKEN"
	deeproxyApiUrlKey     = "DEEPROXY_API_URL"
	FormatHtml            = "html"
	FormatMd              = "md"
	snykCodeTimeoutKey    = "SNYK_CODE_TIMEOUT" // timeout as duration (number + unit), e.g. 10m
	defaultSnykApiUrl     = "https://snyk.io/api"
	defaultDeeproxyApiUrl = "https://deeproxy.snyk.io"
)

var (
	Version       = "SNAPSHOT"
	Development   = "true"
	currentConfig *Config
	mutex         = &sync.Mutex{}
)

type CliSettings struct {
	Insecure             bool
	Endpoint             string
	AdditionalParameters []string
	cliPath              string
	cliPathAccessMutex   sync.Mutex
}

func (c *CliSettings) Installed() bool {
	c.cliPathAccessMutex.Lock()
	defer c.cliPathAccessMutex.Unlock()
	stat, err := os.Stat(c.cliPath)
	return c.cliPath != "" && err == nil && !stat.IsDir()
}

func (c *CliSettings) IsPathDefined() bool {
	c.cliPathAccessMutex.Lock()
	defer c.cliPathAccessMutex.Unlock()
	return c.cliPath != ""
}

func (c *CliSettings) Path() string {
	c.cliPathAccessMutex.Lock()
	defer c.cliPathAccessMutex.Unlock()
	return filepath.Clean(c.cliPath)
}

func (c *CliSettings) SetPath(path string) {
	c.cliPathAccessMutex.Lock()
	defer c.cliPathAccessMutex.Unlock()
	c.cliPath = path
}

type Config struct {
	configLoaded                concurrency.AtomicBool
	cliSettings                 *CliSettings
	configFile                  string
	format                      string
	isErrorReportingEnabled     concurrency.AtomicBool
	isSnykCodeEnabled           concurrency.AtomicBool
	isSnykOssEnabled            concurrency.AtomicBool
	isSnykIacEnabled            concurrency.AtomicBool
	isSnykContainerEnabled      concurrency.AtomicBool
	isSnykAdvisorEnabled        concurrency.AtomicBool
	isTelemetryEnabled          concurrency.AtomicBool
	manageBinariesAutomatically concurrency.AtomicBool
	logPath                     string
	organization                string
	snykCodeAnalysisTimeout     time.Duration
	snykApiUrl                  string
	snykCodeApiUrl              string
	token                       string
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

func New() *Config {
	c := &Config{}
	c.cliSettings = &CliSettings{}
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
	c.token = tokenFromEnv()
	c.clientSettingsFromEnv()
	return c
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
	defer file.Close()
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
				updatePath(v)
			}
		}
	}
	updatePath(".")
	log.Debug().Str("fileName", fileName).Msg("loaded.")
}

func (c *Config) Authenticated() bool       { return c.token != "" }
func (c *Config) CliSettings() *CliSettings { return c.cliSettings }
func (c *Config) Format() string            { return c.format }
func (c *Config) CLIDownloadLockFileName() string {
	return filepath.Join(c.LsPath(), "snyk-cli-download.lock")
}
func (c *Config) IsErrorReportingEnabled() bool          { return c.isErrorReportingEnabled.Get() }
func (c *Config) IsSnykOssEnabled() bool                 { return c.isSnykOssEnabled.Get() }
func (c *Config) IsSnykCodeEnabled() bool                { return c.isSnykCodeEnabled.Get() }
func (c *Config) IsSnykIacEnabled() bool                 { return c.isSnykIacEnabled.Get() }
func (c *Config) IsSnykContainerEnabled() bool           { return c.isSnykContainerEnabled.Get() }
func (c *Config) IsSnykAdvisorEnabled() bool             { return c.isSnykAdvisorEnabled.Get() }
func (c *Config) LogPath() string                        { return c.logPath }
func (c *Config) SnykApi() string                        { return c.snykApiUrl }
func (c *Config) SnykCodeApi() string                    { return c.snykCodeApiUrl }
func (c *Config) SnykCodeAnalysisTimeout() time.Duration { return c.snykCodeAnalysisTimeout }
func (c *Config) Token() string                          { return c.token }

func (c *Config) SetCliSettings(settings *CliSettings) {
	if settings.Endpoint != c.cliSettings.Endpoint {
		// Reset token
		c.token = ""

		// Update Snyk API endpoint
		c.SetSnykApi(settings.Endpoint)

		// Update Code API endpoint
		snykCodeApiUrl, err := getCodeApiUrlFromCustomEndpoint(settings.Endpoint)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't obtain Snyk Code API url from CLI endpoint.")
		}

		c.SetSnykCodeApi(snykCodeApiUrl)
	}

	c.cliSettings = settings
}

func (c *Config) SetSnykApi(snykApiUrl string) {
	if snykApiUrl == "" {
		c.snykApiUrl = defaultSnykApiUrl
		return
	}
	c.snykApiUrl = snykApiUrl
}

func (c *Config) SetSnykCodeApi(snykCodeApiUrl string) {
	if snykCodeApiUrl == "" {
		c.snykCodeApiUrl = defaultDeeproxyApiUrl
		return
	}
	c.snykCodeApiUrl = snykCodeApiUrl
}

func (c *Config) SetErrorReportingEnabled(enabled bool) { c.isErrorReportingEnabled.Set(enabled) }
func (c *Config) SetSnykOssEnabled(enabled bool)        { c.isSnykOssEnabled.Set(enabled) }
func (c *Config) SetSnykCodeEnabled(enabled bool)       { c.isSnykCodeEnabled.Set(enabled) }
func (c *Config) SetSnykIacEnabled(enabled bool)        { c.isSnykIacEnabled.Set(enabled) }

func (c *Config) SetSnykContainerEnabled(enabled bool) { c.isSnykContainerEnabled.Set(enabled) }

func (c *Config) SetSnykAdvisorEnabled(enabled bool) { c.isSnykAdvisorEnabled.Set(enabled) }
func (c *Config) SetToken(token string) {
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
	zerolog.SetGlobalLevel(logLevel)
	zerolog.TimeFieldFormat = time.RFC3339

	if c.logPath != "" {
		file, err := os.OpenFile(c.logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Err(err).Msg("couldn't open logfile")
		}
		log.Info().Msgf("Logging to file %s", c.logPath)
		log.Logger = log.Output(file)
	} else {
		log.Info().Msgf("Logging to console")
	}
}

func (c *Config) SetConfigFile(configFile string) { c.configFile = configFile }

func tokenFromEnv() string { return os.Getenv(SnykTokenKey) }

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

func updatePath(pathExtension string) {
	err := os.Setenv("PATH", os.Getenv("PATH")+string(os.PathListSeparator)+pathExtension)
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

func (c *Config) UserDirFolder() string {
	return "snyk-ls"
}
func (c *Config) LsPath() string {
	lsPath := filepath.Join(xdg.DataHome, "snyk-ls")
	err := os.MkdirAll(lsPath, 0755)
	if err != nil {
		log.Err(err).Str("method", "lsPath").Msgf("couldn't create %s", lsPath)
		return ""
	}
	return lsPath
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
