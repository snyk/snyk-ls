package testutil

import (
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"os"
	"path/filepath"
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
	settings := &config.CliSettings{}
	settings.SetPath("dummy")
	c.SetCliSettings(settings)
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
	cliPath := filepath.Join(t.TempDir(), (&install.Discovery{}).ExecutableName(false))

	c := config.New()
	c.SetToken(GetEnvironmentToken())
	c.SetErrorReportingEnabled(false)
	c.SetTelemetryEnabled(false)
	c.CliSettings().SetPath(cliPath)
	config.SetCurrentConfig(c)

	CLIDownloadLockFileCleanUp(t)
}

func OnlyEnableCodeAndDisableBinaryManagement() {
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(false)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	config.CurrentConfig().SetManageBinariesAutomatically(false)
}
