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

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/cli/filename"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func SetupInitializer(t *testing.T, conf configuration.Configuration, logger *zerolog.Logger, engine workflow.Engine) *Initializer {
	t.Helper()
	return SetupInitializerWithInstaller(t, conf, logger, engine, install.NewFakeInstaller(engine))
}

func SetupInitializerWithInstaller(t *testing.T, conf configuration.Configuration, logger *zerolog.Logger, engine workflow.Engine, installer install.Installer) *Initializer {
	t.Helper()
	return NewInitializer(conf, logger, error_reporting.NewTestErrorReporter(engine),
		installer,
		notification.NewNotifier(),
		getDummyCLI(t, engine))
}

var dummyCLI *TestExecutor

func getDummyCLI(t *testing.T, engine workflow.Engine) *TestExecutor {
	t.Helper()
	if dummyCLI == nil {
		dummyCLI = NewTestExecutorWithResponse(engine, "0.0.0test")
	}
	return dummyCLI
}

func Test_EnsureCliShouldFindOrDownloadCliAndAddPathToEnv(t *testing.T) {
	engine, tokenService := testutil.IntegTestWithEngine(t)
	conf := engine.GetConfiguration()
	initializer := SetupInitializer(t, conf, engine.GetLogger(), engine)
	testutil.CreateDummyProgressListener(t)

	conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), "")
	if config.GetToken(conf) == "" {
		tokenService.SetToken(conf, "dummy") // we don't want to authenticate
	}
	_ = initializer.Init()
	assert.NotEmpty(t, conf.GetString(configresolver.UserGlobalKey(types.SettingCliPath)))
}

func Test_EnsureCLIShouldRespectCliPathInEnv(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	initializer := SetupInitializer(t, conf, engine.GetLogger(), engine)

	tempDir := t.TempDir()
	tempFile := testsupport.CreateTempFile(t, tempDir)
	conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), tempFile.Name())

	_ = initializer.Init()

	assert.Equal(t, tempFile.Name(), conf.GetString(configresolver.UserGlobalKey(types.SettingCliPath)))
}

func TestInitializer_whenNoCli_Installs(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)
	testCliPath := filepath.Join(t.TempDir(), "dummy.cli")
	conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), testCliPath)

	installer := install.NewFakeInstaller(engine)
	initializer := SetupInitializerWithInstaller(t, conf, engine.GetLogger(), engine, installer)

	go func() { _ = initializer.Init() }()

	assert.Eventually(t, func() bool {
		return installer.Installs() > 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenNoCli_InstallsToDefaultCliPath(t *testing.T) {
	testutil.SkipLocally(t)
	engine := testutil.SmokeTest(t, "")
	conf := engine.GetConfiguration()

	// arrange
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)

	clientFunc := func() *http.Client { return http.DefaultClient }
	installer := install.NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), clientFunc)
	initializer := SetupInitializerWithInstaller(t, conf, engine.GetLogger(), engine, installer)

	// ensure CLI is not installed on the system
	existingCliPath, _ := installer.Find()
	for existingCliPath != "" {
		_ = os.RemoveAll(existingCliPath)
		existingCliPath, _ = installer.Find()
	}

	// act
	go func() { _ = initializer.Init() }()

	// assert
	lockFileName, err := config.CLIDownloadLockFileName(conf)
	require.NoError(t, err)
	expectedCliPath := filepath.Join(config.CliDefaultBinaryInstallPath(),
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

	conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), "") // reset CLI path during download for foolproofing

	assert.Eventually(t, func() bool {
		_, err := installer.Find()
		return err == nil
	}, time.Minute*10, time.Second)

	assert.Equal(t, expectedCliPath, conf.GetString(configresolver.UserGlobalKey(types.SettingCliPath)))
}

func TestInitializer_whenBinaryUpdatesNotAllowed_DoesNotInstall(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), false)

	installer := install.NewFakeInstaller(engine)
	initializer := SetupInitializerWithInstaller(t, conf, engine.GetLogger(), engine, installer)

	go func() { _ = initializer.Init() }()
	time.Sleep(time.Second)

	assert.Eventually(t, func() bool {
		return installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenOutdated_Updates(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)
	createDummyCliBinaryWithCreatedDate(t, conf, fiveDaysAgo)

	installer := install.NewFakeInstaller(engine)
	initializer := SetupInitializerWithInstaller(t, conf, engine.GetLogger(), engine, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 1 && installer.Installs() == 0
	}, time.Minute, time.Millisecond)
}

func TestInitializer_whenUpToDate_DoesNotUpdates(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)
	threeDaysAgo := time.Now().Add(time.Hour * 24 * 3) // exactly 4 days is considered as not outdated.
	createDummyCliBinaryWithCreatedDate(t, conf, threeDaysAgo)

	installer := install.NewFakeInstaller(engine)
	initializer := SetupInitializerWithInstaller(t, conf, engine.GetLogger(), engine, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 0 && installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesNotAllowed_PreventsUpdate(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), false)
	createDummyCliBinaryWithCreatedDate(t, conf, fiveDaysAgo)

	installer := install.NewFakeInstaller(engine)
	initializer := SetupInitializerWithInstaller(t, conf, engine.GetLogger(), engine, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 0
	}, time.Second*60, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesNotAllowed_PreventsInstall(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), false)

	installer := install.NewFakeInstaller(engine)
	initializer := SetupInitializerWithInstaller(t, conf, engine.GetLogger(), engine, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesAllowed_Updates(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)
	createDummyCliBinaryWithCreatedDate(t, conf, fiveDaysAgo)

	installer := install.NewFakeInstaller(engine)
	initializer := SetupInitializerWithInstaller(t, conf, engine.GetLogger(), engine, installer)

	_ = initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 1 && installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func createDummyCliBinaryWithCreatedDate(t *testing.T, conf configuration.Configuration, binaryCreationDate time.Time) {
	t.Helper()
	// prepare user directory with OS specific dummy CLI binary
	temp := t.TempDir()
	file := testsupport.CreateTempFile(t, temp)

	conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), file.Name())

	err := os.Chtimes(file.Name(), binaryCreationDate, binaryCreationDate)
	if err != nil {
		t.Fatal("Failed to set the access and modification times of the temp cli file")
	}
}

var fiveDaysAgo = time.Now().Add(-time.Hour * 24 * 5)
