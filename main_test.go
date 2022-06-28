package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_shouldSetLogLevelViaFlag(t *testing.T) {
	args := []string{"snyk-ls", "-l", "debug"}
	_, _ = parseFlags(args)
	assert.Equal(t, zerolog.DebugLevel, zerolog.GlobalLevel())
}

func Test_shouldSetLogFileViaFlag(t *testing.T) {
	args := []string{"snyk-ls", "-f", "a.txt"}
	defer func() {
		_ = os.Remove("a.txt")
	}()
	_, _ = parseFlags(args)
	assert.Equal(t, config.CurrentConfig().LogPath(), "a.txt")
}

func Test_shouldSetOutputFormatViaFlag(t *testing.T) {
	args := []string{"snyk-ls", "-o", config.FormatHtml}
	_, _ = parseFlags(args)
	assert.Equal(t, config.FormatHtml, config.CurrentConfig().Format())
}

func Test_shouldShowUsageOnUnknownFlag(t *testing.T) {
	args := []string{"snyk-ls", "-unknown", config.FormatHtml}

	output, err := parseFlags(args)

	assert.True(t, strings.Contains(output, "Usage of snyk-ls"))
	assert.NotNil(t, err)
}
func Test_shouldSetLoadConfigFromFlag(t *testing.T) {
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

	t.Setenv("Bb", "")

	_, _ = parseFlags(args)
	assert.Equal(t, "Bb", os.Getenv("AA"))
}

func Test_shouldSetReportErrorsViaFlag(t *testing.T) {
	testutil.UnitTest(t)
	args := []string{"snyk-ls"}
	_, _ = parseFlags(args)

	assert.False(t, config.CurrentConfig().IsErrorReportingEnabled())

	args = []string{"snyk-ls", "-reportErrors"}
	_, _ = parseFlags(args)
	assert.True(t, config.CurrentConfig().IsErrorReportingEnabled())
}

func Test_ConfigureLoggingShouldAddFileLogger(t *testing.T) {
	testutil.UnitTest(t)
	logPath, err := os.MkdirTemp(os.TempDir(), "testlogconfig")
	if err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(logPath, "a.txt")
	config.CurrentConfig().SetLogPath(logFile)
	defer func(name string) {
		file, _ := os.Open(logFile)
		file.Close()
		err := os.RemoveAll(logPath)
		if err != nil {
			t.Logf("clean up didn't work")
		}
		config.CurrentConfig().SetLogPath("")
	}(logPath)

	config.CurrentConfig().ConfigureLogging("debug")
	log.Error().Msg("test")

	assert.Eventuallyf(t, func() bool {
		bytes, err := os.ReadFile(config.CurrentConfig().LogPath())
		fmt.Println("Read file " + config.CurrentConfig().LogPath())
		if err != nil {
			return false
		}
		fmt.Println("Read bytes:" + string(bytes)) // no logger usage here
		return len(bytes) > 0
	}, 2*time.Second, 10*time.Millisecond, "didn't write to logfile")
}
