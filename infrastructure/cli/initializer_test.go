package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_EnsureCliShouldFindOrDownloadCliAndAddPathToEnv(t *testing.T) {
	testutil.IntegTest(t)
	initializer := NewInitializer(error_reporting.NewTestErrorReporter(), install.NewTestInstaller())
	testutil.CreateDummyProgressListener(t)

	config.CurrentConfig().CliSettings().SetPath("")
	if !config.CurrentConfig().Authenticated() {
		config.CurrentConfig().SetToken("dummy") // we don't want to authenticate
	}
	initializer.Init()
	assert.NotEmpty(t, config.CurrentConfig().CliSettings().Path())
}

func Test_EnsureCLIShouldRespectCliPathInEnv(t *testing.T) {
	testutil.UnitTest(t)
	initializer := NewInitializer(error_reporting.NewTestErrorReporter(), install.NewTestInstaller())

	tempDir := t.TempDir()
	tempFile := testutil.CreateTempFile(tempDir, t)
	config.CurrentConfig().CliSettings().SetPath(tempFile.Name())
	defer func() {
		config.CurrentConfig().CliSettings().SetPath("")
	}()

	initializer.Init()

	assert.Equal(t, tempFile.Name(), config.CurrentConfig().CliSettings().Path())
}

func TestInitializer_whenNoCli_Installs(t *testing.T) {
	config.CurrentConfig().SetManageBinariesAutomatically(true)
	settings := &config.CliSettings{}
	testCliPath := filepath.Join(t.TempDir(), "dummy.cli")
	settings.SetPath(testCliPath)
	config.CurrentConfig().SetCliSettings(settings)

	installer := install.NewTestInstaller()
	initializer := NewInitializer(error_reporting.NewTestErrorReporter(), installer)

	go initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Installs() > 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesNotAllowed_DoesNotInstall(t *testing.T) {
	config.CurrentConfig().SetManageBinariesAutomatically(false)

	installer := install.NewTestInstaller()
	initializer := NewInitializer(error_reporting.NewTestErrorReporter(), installer)

	go initializer.Init()
	time.Sleep(time.Second)

	assert.Eventually(t, func() bool {
		return installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenOutdated_Updates(t *testing.T) {
	config.CurrentConfig().SetManageBinariesAutomatically(true)
	createDummyCliBinaryWithCreatedDate(t, fiveDaysAgo)

	installer := install.NewTestInstaller()
	initializer := NewInitializer(error_reporting.NewTestErrorReporter(), installer)

	initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 1 && installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenUpToDate_DoesNotUpdates(t *testing.T) {
	config.CurrentConfig().SetManageBinariesAutomatically(true)
	threeDaysAgo := time.Now().Add(time.Hour * 24 * 3) // exactly 4 days is considered as not outdated.
	createDummyCliBinaryWithCreatedDate(t, threeDaysAgo)

	installer := install.NewTestInstaller()
	initializer := NewInitializer(error_reporting.NewTestErrorReporter(), installer)

	initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 0 && installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesNotAllowed_PreventsUpdate(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetManageBinariesAutomatically(false)
	createDummyCliBinaryWithCreatedDate(t, fiveDaysAgo)

	installer := install.NewTestInstaller()
	initializer := NewInitializer(error_reporting.NewTestErrorReporter(), installer)

	initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesNotAllowed_PreventsInstall(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetManageBinariesAutomatically(false)

	installer := install.NewTestInstaller()
	initializer := NewInitializer(error_reporting.NewTestErrorReporter(), installer)

	initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func TestInitializer_whenBinaryUpdatesAllowed_Updates(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetManageBinariesAutomatically(true)
	createDummyCliBinaryWithCreatedDate(t, fiveDaysAgo)

	installer := install.NewTestInstaller()
	initializer := NewInitializer(error_reporting.NewTestErrorReporter(), installer)

	initializer.Init()

	assert.Eventually(t, func() bool {
		return installer.Updates() == 1 && installer.Installs() == 0
	}, time.Second, time.Millisecond)
}

func createDummyCliBinaryWithCreatedDate(t *testing.T, binaryCreationDate time.Time) {
	// prepare user directory with OS specific dummy CLI binary
	temp := t.TempDir()
	file := testutil.CreateTempFile(temp, t)

	config.CurrentConfig().CliSettings().SetPath(file.Name())

	err := os.Chtimes(file.Name(), binaryCreationDate, binaryCreationDate)
	if err != nil {
		t.Fatal(t, "Failed to set the access and modification times of the temp cli file")
	}
}

var fiveDaysAgo = time.Now().Add(-time.Hour * 24 * 5)
