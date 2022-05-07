package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/config/environment"
)

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
	t.Setenv("Bb", "")
	environment.Load()

	assert.Equal(t, "Bb", os.Getenv("AA"))
}

func Test_shouldSetReportErrorsViaFlag(t *testing.T) {
	args := []string{"snyk-ls"}
	_, _ = parseFlags(args)
	assert.False(t, config.IsErrorReportingEnabled)

	args = []string{"snyk-ls", "-reportErrors"}
	_, _ = parseFlags(args)
	assert.True(t, config.IsErrorReportingEnabled)
}
