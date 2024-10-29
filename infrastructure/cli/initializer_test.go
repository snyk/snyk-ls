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

package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/cli/filename"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func SetupInitializer(t *testing.T) *Initializer {
	t.Helper()
	return SetupInitializerWithInstaller(t, install.NewFakeInstaller())
}

func SetupInitializerWithInstaller(t *testing.T, installer install.Installer) *Initializer {
	t.Helper()
	return NewInitializer(error_reporting.NewTestErrorReporter(),
		installer,
		notification.NewNotifier(),
		dummyCli)
}

func Test_EnsureCliShouldFindOrDownloadCliAndAddPathToEnv(t *testing.T) {
	c := testutil.IntegTest(t)
	initializer := SetupInitializer(t)
	testutil.CreateDummyProgressListener(t)

	c.CliSettings().SetPath("")
	if !c.NonEmptyToken() {
		c.SetToken("dummy") // we don't want to authenticate
	}
	_ = initializer.Init()
	assert.NotEmpty(t, c.CliSettings().Path())
}

func Test_EnsureCLIShouldRespectCliPathInEnv(t *testing.T) {
	c := testutil.UnitTest(t)
	initializer := SetupInitializer(t)

	tempDir := t.TempDir()
	tempFile := testutil.CreateTempFile(t, tempDir)
	c.CliSettings().SetPath(tempFile.Name())

	_ = initializer.Init()

	assert.Equal(t, tempFile.Name(), c.CliSettings().Path())
}

func TestInitializer_whenNoCli_Installs(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetManageBinariesAutomatically(true)
	settings := &config.CliSettings{C: c}
	testCliPath := filepath.Join(t.TempDir(), "dummy.cli")
	settings.SetPath(testCliPath)
	c.SetCliSettings(settings)

	installer := install.NewFakeInstaller()
	initializer := SetupInitializerWithInstaller(t, installer)

	go func() { _ = initializer.Init() }()

	assert.Eventually(t, func() bool {
		return installer.Installs() > 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenNoCli_InstallsToDefaultCliPath(t *testing.T) {
	c := testutil.SmokeTest(t, false)

	// arrange
	c.SetManageBinariesAutomatically(true)

	clientFunc := func() *http.Client { return http.DefaultClient }
	installer := install.NewInstaller(error_reporting.NewTestErrorReporter(), clientFunc)
	initializer := SetupInitializerWithInstaller(t, installer)

	// ensure CLI is not installed on the system
	existingCliPath, _ := installer.Find()
	for existingCliPath != "" {
		_ = os.RemoveAll(existingCliPath)
		existingCliPath, _ = installer.Find()
	}

	// act
	go func() { _ = initializer.Init() }()

	// assert
	lockFileName := c.CLIDownloadLockFileName()
	expectedCliPath := filepath.Join(c.CliSettings().DefaultBinaryInstallPath(),
		filename.ExecutableName)

	defer func() { // defer clean up
		_, err := os.Stat(lockFileName)
		if err == nil {
			_ = os.RemoveAll(lockFileName)
		}
		_, err = os.Stat(expectedCliPath)
		if err == nil {
			_ = os.RemoveAll(expectedCliPath)
		}
	}()

	assert.Eventually(t, func() bool {
		_, err := os.Stat(lockFileName)
		return err != nil
	}, time.Second*10, time.Millisecond)

	c.CliSettings().SetPath("") // reset CLI path during download for foolproofing

	assert.Eventually(t, func() bool {
		_, err := installer.Find()
		return err == nil
	}, time.Minute*10, time.Second)

	assert.Equal(t, expectedCliPath, c.CliSettings().Path())
}

func TestInitializer_whenBinaryUpdatesNotAllowed_DoesNotInstall(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetManageBinariesAutomatically(false)

	installer := install.NewFakeInstaller()
	initializer := SetupInitializerWithInstaller(t, installer)

	go func() { _ = initializer.Init() }()
	time.Sleep(time.Second)

	assert.Eventually(t, func() bool {
		return installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenOutdated_Updates(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetManageBinariesAutomatically(true)
	createDummyCliBinaryWithCreatedDate(t, c, fiveDaysAgo)

	installer := install.NewFakeInstaller()
	initializer := SetupInitializerWithInstaller(t, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 1 && installer.Installs() == 0
	}, time.Second*5, time.Millisecond)
}

func TestInitializer_whenUpToDate_DoesNotUpdates(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetManageBinariesAutomatically(true)
	threeDaysAgo := time.Now().Add(time.Hour * 24 * 3) // exactly 4 days is considered as not outdated.
	createDummyCliBinaryWithCreatedDate(t, c, threeDaysAgo)

	installer := install.NewFakeInstaller()
	initializer := SetupInitializerWithInstaller(t, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 0 && installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesNotAllowed_PreventsUpdate(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetManageBinariesAutomatically(false)
	createDummyCliBinaryWithCreatedDate(t, c, fiveDaysAgo)

	installer := install.NewFakeInstaller()
	initializer := SetupInitializerWithInstaller(t, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesNotAllowed_PreventsInstall(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetManageBinariesAutomatically(false)

	installer := install.NewFakeInstaller()
	initializer := SetupInitializerWithInstaller(t, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesAllowed_Updates(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetManageBinariesAutomatically(true)
	createDummyCliBinaryWithCreatedDate(t, c, fiveDaysAgo)

	installer := install.NewFakeInstaller()
	initializer := SetupInitializerWithInstaller(t, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 1 && installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func createDummyCliBinaryWithCreatedDate(t *testing.T, c *config.Config, binaryCreationDate time.Time) {
	t.Helper()
	// prepare user directory with OS specific dummy CLI binary
	temp := t.TempDir()
	file := testutil.CreateTempFile(t, temp)

	c.CliSettings().SetPath(file.Name())

	err := os.Chtimes(file.Name(), binaryCreationDate, binaryCreationDate)
	if err != nil {
		t.Fatal(t, "Failed to set the access and modification times of the temp cli file")
	}
}

var fiveDaysAgo = time.Now().Add(-time.Hour * 24 * 5)

var dummyCli = NewTestExecutorWithResponse("0.0.0test")
