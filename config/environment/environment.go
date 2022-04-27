package environment

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/subosito/gotenv"
)

const (
	cliPathKey         = "SNYK_CLI_PATH"
	snykTokenKey       = "SNYK_TOKEN"
	deeproxyApiUrlKey  = "DEEPROXY_API_URL"
	snykCodeTimeoutKey = "SNYK_CODE_TIMEOUT" // timeout as duration (number + unit), e.g. 10m
	FormatHtml         = "html"
	FormatMd           = "md"
)

var (
	configLoaded = false
	Format       = "md"
	ConfigFile   = ""
	LogPath      string
)

func SnykCodeAnalysisTimeout() time.Duration {
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

func getValue(key string) string {
	if !configLoaded {
		Load()
	}
	return os.Getenv(key)
}

func Token() string {
	return getValue(snykTokenKey)
}

func SetToken(token string) error {
	return os.Setenv(snykTokenKey, token)
}

func ApiUrl() string {
	trim := strings.Trim(getValue(deeproxyApiUrlKey), "/")
	if trim == "" {
		trim = "https://deeproxy.snyk.io"
	}
	return trim
}

func CliPath() string {
	return getValue(cliPathKey)
}

func Load() {
	files := configFiles()
	for _, fileName := range files {
		loadFile(fileName)
	}

	configLoaded = true
}

func loadFile(fileName string) {
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

func updatePath(pathExtension string) {
	err := os.Setenv("PATH", os.Getenv("PATH")+string(os.PathListSeparator)+pathExtension)
	if err != nil {
		log.Warn().Str("method", "loadFile").Msg("Couldn't update path ")
	}
}

func Authenticated() bool {
	return Token() != ""
}

func CliInstalled() bool {
	cliInstalled := os.Getenv(cliPathKey) != ""
	return cliInstalled
}

func SetCliPath(cliPath string) error { return os.Setenv(cliPathKey, cliPath) }

// The order of the files is important - first file variable definitions win!
func configFiles() []string {
	var files []string
	if ConfigFile != "" {
		files = append(files, ConfigFile)
	}
	home := os.Getenv("HOME")
	stdFiles := []string{
		".snyk.env",
		home + "/.snyk.env",
		home + "/.zshrc.local",
		home + "/.zshrc",
		home + "/.bashrc",
		home + "/.profile",
		"/etc/launchd.conf",
		"/etc/profile",
		"/etc/environment",
	}
	return append(files, stdFiles...)
}
