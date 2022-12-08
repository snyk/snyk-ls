/*
 * Copyright 2022 Snyk Ltd.
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

	"github.com/pact-foundation/pact-go/dsl"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/progress"
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
	c.SetManageBinariesAutomatically(false)
	c.SetToken("00000000-0000-0000-0000-000000000001")
	c.SetTrustedFolderFeatureEnabled(false)
	config.SetCurrentConfig(c)
	CLIDownloadLockFileCleanUp(t)
}

func CLIDownloadLockFileCleanUp(t *testing.T) {
	t.Helper()
	// remove lock file before test and after test
	lockFileName := config.CurrentConfig().CLIDownloadLockFileName()
	file, _ := os.Open(lockFileName)
	file.Close()
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

func Pact(t *testing.T, pactDir string, provider string) *dsl.Pact {
	t.Helper()
	NotOnWindows(t, "we don't have a pact cli")
	pact := &dsl.Pact{
		Consumer: "SnykLS",
		Provider: provider,
		PactDir:  pactDir,
	}
	t.Cleanup(func() {
		pact.Teardown()
	})
	return pact
}

func CreateDummyProgressListener(t *testing.T) {
	t.Helper()
	var dummyProgressStopChannel = make(chan bool, 1)

	t.Cleanup(func() {
		dummyProgressStopChannel <- true
	})

	go func() {
		for {
			select {
			case <-progress.Channel:
				continue
			case <-dummyProgressStopChannel:
				return
			}
		}
	}()

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
}

func OnlyEnableCodeAndDisableBinaryManagement() {
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(false)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	config.CurrentConfig().SetManageBinariesAutomatically(false)
}
