package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/config/environment"
)

func Test_shouldSetLogLevelViaFlag(t *testing.T) {
	args := []string{"snyk-ls", "-l", "debug"}
	_, _ = parseFlags(args)
	assert.Equal(t, zerolog.DebugLevel, zerolog.GlobalLevel())
}

func Test_shouldSetLogFileViaFlag(t *testing.T) {
	args := []string{"snyk-ls", "-f", "a.txt"}
	_, _ = parseFlags(args)
	assert.Equal(t, environment.LogPath, "a.txt")
}

func Test_shouldSetOutputFormatViaFlag(t *testing.T) {
	args := []string{"snyk-ls", "-o", environment.FormatHtml}
	_, _ = parseFlags(args)
	assert.Equal(t, environment.FormatHtml, environment.Format)
}

func Test_shouldShowUsageOnUnknownFlag(t *testing.T) {
	args := []string{"snyk-ls", "-unknown", environment.FormatHtml}

	output, err := parseFlags(args)

	assert.True(t, strings.Contains(output, "Usage of snyk-ls"))
	assert.NotNil(t, err)
}
func Test_shouldSetLoadConfigFromFlag(t *testing.T) {
	os.Clearenv()
	file, err := os.CreateTemp(".", "configFlagTest")
	if err != nil {
		assert.Fail(t, "Couldn't create test file")
	}
	defer func(file *os.File) {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}(file)

	_, err = file.Write([]byte("AA=Bb"))
	if err != nil {
		assert.Fail(t, "Couldn't write to test file")
	}
	args := []string{"snyk-ls", "-c", file.Name()}

	_, _ = parseFlags(args)
	environment.Load()

	assert.Equal(t, "Bb", os.Getenv("AA"))
	os.Clearenv()
}

func Test_shouldSetReportErrorsViaFlag(t *testing.T) {
	args := []string{"snyk-ls"}
	_, _ = parseFlags(args)
	assert.False(t, config.IsErrorReportingEnabled)

	args = []string{"snyk-ls", "-reportErrors"}
	_, _ = parseFlags(args)
	assert.True(t, config.IsErrorReportingEnabled)
}

func Test_ConfigureLoggingShouldAddFileLogger(t *testing.T) {
	logPath, err := os.MkdirTemp(os.TempDir(), "testlogconfig")
	if err != nil {
		t.Fatal(err)
	}
	environment.LogPath = filepath.Join(logPath, "a.txt")
	defer func(name string) {
		err := os.RemoveAll(logPath)
		if err != nil {
			t.Fatal(err)
		}
		environment.LogPath = ""
	}(logPath)

	configureLogging("debug")
	log.Error().Msg("test")

	assert.Eventuallyf(t, func() bool {
		bytes, err := os.ReadFile(environment.LogPath)
		if err != nil {
			t.Fatal("Couldn't read logfile")
		}
		return len(bytes) == 70
	}, 2*time.Second, 10*time.Millisecond, "didn't write to logfile")

}
