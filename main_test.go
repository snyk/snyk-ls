package main

import (
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-lsp/util"
)

func Test_shouldSetLogLevelViaFlag(t *testing.T) {
	args := []string{"snyk-lsp", "-l", "debug"}
	_, _ = parseFlags(args)
	assert.Equal(t, zerolog.DebugLevel, zerolog.GlobalLevel())
}

func Test_shouldSetOutputFormatViaFlag(t *testing.T) {
	args := []string{"snyk-lsp", "-o", util.FormatHtml}
	_, _ = parseFlags(args)
	assert.Equal(t, util.FormatHtml, util.Format)
}

func Test_shouldShowUsageOnUnknownFlag(t *testing.T) {
	args := []string{"snyk-lsp", "-unknown", util.FormatHtml}

	output, err := parseFlags(args)

	assert.True(t, strings.Contains(output, "Usage of snyk-lsp"))
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
	args := []string{"snyk-lsp", "-c", file.Name()}

	_, _ = parseFlags(args)
	util.Load()

	assert.Equal(t, "Bb", os.Getenv("AA"))
	os.Clearenv()
}
