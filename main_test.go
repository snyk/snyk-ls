package main

import (
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-lsp/util"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

func Test_shouldSetLogLevelViaFlag(t *testing.T) {
	args := []string{"snyk-lsp", "-l", "debug"}
	parseFlags(args)
	assert.Equal(t, zerolog.DebugLevel, zerolog.GlobalLevel())
}

func Test_shouldSetOutputFormatViaFlag(t *testing.T) {
	args := []string{"snyk-lsp", "-o", util.FormatHtml}
	parseFlags(args)
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
	defer file.Close()
	defer os.Remove(file.Name())
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
