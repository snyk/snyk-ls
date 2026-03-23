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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_shouldSetLogLevelViaFlag(t *testing.T) {
	args := []string{"snyk-ls", "-l", "debug"}
	engine, _ := config.InitEngine(nil)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingBinarySearchPaths), []string{})
	require.NoError(t, types.WaitForDefaultEnv(t.Context(), engine.GetConfiguration()))
	_, _ = parseFlags(args, engine.GetConfiguration())
	assert.Equal(t, zerolog.DebugLevel, zerolog.GlobalLevel())
}

func Test_shouldSetLogFileViaFlag(t *testing.T) {
	args := []string{"snyk-ls", "-f", "a.txt"}
	engine, _ := config.InitEngine(nil)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingBinarySearchPaths), []string{})
	require.NoError(t, types.WaitForDefaultEnv(t.Context(), engine.GetConfiguration()))
	t.Cleanup(func() {
		config.DisableFileLogging(engine.GetConfiguration(), engine.GetLogger())

		err := os.Remove("a.txt")
		if err != nil {
			t.Logf("Error when trying to cleanup logfile: %e", err)
		}
	})

	_, _ = parseFlags(args, engine.GetConfiguration())
	assert.Equal(t, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingLogPath)), "a.txt")
}

func Test_shouldSetOutputFormatViaFlag(t *testing.T) {
	args := []string{"snyk-ls", "-o", config.FormatHtml}
	engine, _ := config.InitEngine(nil)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingBinarySearchPaths), []string{})
	require.NoError(t, types.WaitForDefaultEnv(t.Context(), engine.GetConfiguration()))
	_, _ = parseFlags(args, engine.GetConfiguration())
	assert.Equal(t, config.FormatHtml, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingFormat)))
}

func Test_shouldDisplayLicenseInformationWithFlag(t *testing.T) {
	args := []string{"snyk-ls", "-licenses"}
	engine, _ := config.InitEngine(nil)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingBinarySearchPaths), []string{})
	require.NoError(t, types.WaitForDefaultEnv(t.Context(), engine.GetConfiguration()))
	output, _ := parseFlags(args, engine.GetConfiguration())
	assert.True(t, strings.Contains(output, "License information"))
}

func Test_shouldReturnErrorWithVersionStringOnFlag(t *testing.T) {
	args := []string{"snyk-ls", "-v"}
	engine, _ := config.InitEngine(nil)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingBinarySearchPaths), []string{})
	require.NoError(t, types.WaitForDefaultEnv(t.Context(), engine.GetConfiguration()))
	output, err := parseFlags(args, engine.GetConfiguration())
	assert.Error(t, err)
	assert.Empty(t, output)
	assert.Equal(t, config.Version, err.Error())
}

func Test_shouldSetReportErrorsViaFlag(t *testing.T) {
	engine := testutil.UnitTest(t)
	args := []string{"snyk-ls"}
	_, _ = parseFlags(args, engine.GetConfiguration())

	assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSendErrorReports)))

	args = []string{"snyk-ls", "-reportErrors"}
	_, _ = parseFlags(args, engine.GetConfiguration())
	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSendErrorReports)))
}

func Test_ConfigureLoggingShouldAddFileLogger(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	logPath := t.TempDir()
	logFile := filepath.Join(logPath, "a.txt")
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingLogPath), logFile)
	t.Cleanup(func() {
		config.DisableFileLogging(engine.GetConfiguration(), engine.GetLogger())
	})

	config.SetupLogging(engine, tokenService, nil)
	engine.GetLogger().Error().Msg("test")

	assert.Eventuallyf(t, func() bool {
		bytes, err := os.ReadFile(engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingLogPath)))
		if err != nil {
			return false
		}
		return len(bytes) > 0
	}, 2*time.Second, 10*time.Millisecond, "didn't write to logfile")
}
