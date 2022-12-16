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
	t.Cleanup(func() {
		config.CurrentConfig().DisableLoggingToFile()

		err := os.Remove("a.txt")
		if err != nil {
			t.Logf("Error when trying to cleanup logfile: %e", err)
		}
	})

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

func Test_shouldDisplayLicenseInformationWithFlag(t *testing.T) {
	args := []string{"snyk-ls", "-licenses"}
	output, _ := parseFlags(args)
	assert.True(t, strings.Contains(output, "License information"))
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
	logPath := t.TempDir()
	logFile := filepath.Join(logPath, "a.txt")
	config.CurrentConfig().SetLogPath(logFile)
	t.Cleanup(func() {
		config.CurrentConfig().DisableLoggingToFile()
	})

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
