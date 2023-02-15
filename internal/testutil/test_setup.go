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

package testutil

import (
	"os"
	"runtime"
	"testing"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
)

const (
	integTestEnvVar = "INTEG_TESTS"
	smokeTestEnvVar = "SMOKE_TESTS"
)

func IntegTest(t *testing.T) {
	prepareTestHelper(t, integTestEnvVar)
}

func SmokeTest(t *testing.T) {
	prepareTestHelper(t, smokeTestEnvVar)
}

func UnitTest(t *testing.T) {
	t.Helper()
	c := config.New()
	c.SetToken("00000000-0000-0000-0000-000000000001")
	c.SetTrustedFolderFeatureEnabled(false)
	config.SetCurrentConfig(c)
	CLIDownloadLockFileCleanUp(t)
	notification.DisposeListener()
	t.Cleanup(func() {
		notification.DisposeListener()
		cleanupFakeCliFile(c)
	})
}

func cleanupFakeCliFile(c *config.Config) {
	stat, err := os.Stat(c.CliSettings().Path())
	if err != nil {
		return
	}
	if stat.Size() < 1000 {
		// this is a fake CLI, removing it
		err = os.Remove(c.CliSettings().Path())
		if err != nil {
			log.Warn().Err(err).Msg("Failed to remove fake CLI")
		}
	}
}

func CLIDownloadLockFileCleanUp(t *testing.T) {
	t.Helper()
	// remove lock file before test and after test
	lockFileName := config.CurrentConfig().CLIDownloadLockFileName()
	file, _ := os.Open(lockFileName)
	_ = file.Close()
	_ = os.Remove(lockFileName)
	t.Cleanup(func() {
		_ = os.Remove(lockFileName)
	})
}

func NotOnWindows(t *testing.T, reason string) {
	t.Helper()
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		t.Skipf("Not on windows, because %s", reason)
	}
}

func OnlyOnWindows(t *testing.T, reason string) {
	t.Helper()
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS != "windows" {
		t.Skipf("Only on windows, because %s", reason)
	}
}

func prepareTestHelper(t *testing.T, envVar string) {
	t.Helper()
	if os.Getenv(envVar) == "" {
		t.Logf("%s is not set", envVar)
		t.SkipNow()
	}

	c := config.New()
	c.SetToken(GetEnvironmentToken())
	c.SetErrorReportingEnabled(false)
	c.SetTelemetryEnabled(false)
	c.SetTrustedFolderFeatureEnabled(false)
	config.SetCurrentConfig(c)
	CLIDownloadLockFileCleanUp(t)
	t.Cleanup(func() {
		notification.DisposeListener()
		cleanupFakeCliFile(c)
	})
}

func OnlyEnableCode() {
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(false)
	config.CurrentConfig().SetSnykCodeEnabled(true)
}
