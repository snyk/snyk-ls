package testutil

import (
	"os"
	"runtime"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/progress"
)

const integTestEnvVar = "INTEG_TESTS"

func IntegTest(t *testing.T) {
	t.Helper()
	if os.Getenv(integTestEnvVar) == "" {
		t.Logf("%s is not set", integTestEnvVar)
		t.SkipNow()
	}
	config.SetCurrentConfig(config.New())
	CLIDownloadLockFileCleanUp(t)
}

func UnitTest(t *testing.T) {
	t.Helper()
	config.SetCurrentConfig(config.New())
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
	if runtime.GOOS == "windows" {
		t.Skipf("Not on windows, because %s", reason)
	}
}

func OnlyOnWindows(t *testing.T, reason string) {
	t.Helper()
	if runtime.GOOS != "windows" {
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
