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
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/constants"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/storage"
	storedConfig "github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/types"
)

func IntegTest(t *testing.T) *config.Config {
	t.Helper()
	return prepareTestHelper(t, testsupport.IntegTestEnvVar, false)
}

// TODO: remove useConsistentIgnores once we have fully rolled out the feature
func SmokeTest(t *testing.T, useConsistentIgnores bool) *config.Config {
	t.Helper()
	return prepareTestHelper(t, testsupport.SmokeTestEnvVar, useConsistentIgnores)
}

func UnitTest(t *testing.T) *config.Config {
	t.Helper()
	c := config.New()
	// we don't want server logging in test runs
	c.ConfigureLogging(nil)
	c.SetToken("00000000-0000-0000-0000-000000000001")
	c.SetTrustedFolderFeatureEnabled(false)
	c.SetAuthenticationMethod(types.FakeAuthentication)
	setMCPServerURL(t, c)
	redirectConfigAndDataHome(t, c)
	config.SetCurrentConfig(c)
	CLIDownloadLockFileCleanUp(t)
	t.Cleanup(func() {
		cleanupFakeCliFile(c)
		progress.CleanupChannels()
	})
	return c
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
			c.Logger().Warn().Err(err).Msg("Failed to remove fake CLI")
		}
	}
}

func CLIDownloadLockFileCleanUp(t *testing.T) {
	t.Helper()
	// remove lock file before test and after test
	lockFileName, _ := config.CurrentConfig().CLIDownloadLockFileName()
	file, _ := os.Open(lockFileName)
	_ = file.Close()
	_ = os.Remove(lockFileName)
	t.Cleanup(func() {
		_ = os.Remove(lockFileName)
	})
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
			case <-progress.ToServerProgressChannel:
				continue
			case <-dummyProgressStopChannel:
				return
			}
		}
	}()
}

func prepareTestHelper(t *testing.T, envVar string, useConsistentIgnores bool) *config.Config {
	t.Helper()
	if os.Getenv(envVar) == "" {
		t.Logf("%s is not set", envVar)
		t.SkipNow()
	}

	c := config.New()
	c.ConfigureLogging(nil)
	c.SetToken(testsupport.GetEnvironmentToken(useConsistentIgnores))
	c.SetAuthenticationMethod(types.TokenAuthentication)
	c.SetErrorReportingEnabled(false)
	c.SetTrustedFolderFeatureEnabled(false)
	c.SetIssueViewOptions(types.IssueViewOptions{OpenIssues: true, IgnoredIssues: true})
	setMCPServerURL(t, c)
	redirectConfigAndDataHome(t, c)

	config.SetCurrentConfig(c)
	CLIDownloadLockFileCleanUp(t)
	t.Cleanup(func() {
		cleanupFakeCliFile(c)
	})
	return c
}

func setMCPServerURL(t *testing.T, c *config.Config) {
	t.Helper()
	u, err := url.Parse("http://localhost:1111")
	require.NoError(t, err)
	c.SetMCPServerURL(u)
}

func redirectConfigAndDataHome(t *testing.T, c *config.Config) {
	t.Helper()
	conf := c.Engine().GetConfiguration()
	conf.Set(constants.DataHome, t.TempDir())
	storageFile := filepath.Join(t.TempDir(), "testStorage")
	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.PersistInStorage(storedConfig.ConfigMainKey)
	conf.SetStorage(s)
}

func OnlyEnableCode() {
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(false)
	config.CurrentConfig().SetSnykCodeEnabled(true)
}

func SetUpEngineMock(t *testing.T, c *config.Config) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()
	mockEngine, engineConfig := testsupport.SetupEngineMock(t)
	c.SetEngine(mockEngine)
	return mockEngine, engineConfig
}
