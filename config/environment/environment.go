package environment

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/snyk/go-common/log"
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
	LogLevel     log.Level
	Logger       log.Logger
)

func init() {
	LogLevel = log.Debug
	Logger = log.SnykDefaultLogger("Snyk LS", false, LogLevel)
}

func SnykCodeAnalysisTimeout(ctx context.Context) time.Duration {
	var snykCodeTimeout time.Duration
	var err error
	env := os.Getenv(snykCodeTimeoutKey)
	if env == "" {
		snykCodeTimeout = 10 * time.Minute
	} else {
		snykCodeTimeout, err = time.ParseDuration(env)
		if err != nil {
			Logger.Error(ctx, "couldn't convert timeout env variable to integer")
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
		loadFile(context.Background(), fileName)
	}

	configLoaded = true
}

func loadFile(ctx context.Context, fileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		Logger.WithField("method", "loadFile").Info(ctx, "Couldn't load "+fileName)
		return
	}
	defer file.Close()
	env := gotenv.Parse(file)
	for k, v := range env {
		_, exists := os.LookupEnv(k)
		if !exists {
			err := os.Setenv(k, v)
			if err != nil {
				Logger.WithField("method", "loadFile").Warn(ctx, "Couldn't set environment variable "+k)
			}
		} else {
			// add to path, don't ignore additional paths
			if k == "PATH" {
				updatePath(ctx, v)
			}
		}
	}
	updatePath(ctx, ".")
	Logger.
		WithField("method", "loadFile").
		WithField("fileName", fileName).
		Debug(ctx, "loaded")
}

func updatePath(ctx context.Context, pathExtension string) {
	err := os.Setenv("PATH", os.Getenv("PATH")+string(os.PathListSeparator)+pathExtension)
	if err != nil {
		Logger.WithField("method", "loadFile").Warn(ctx, "Couldn't update path")
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
