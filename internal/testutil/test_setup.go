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
	config.CurrentConfig = config.New()
}

func UnitTest(t *testing.T) {
	t.Helper()
	config.CurrentConfig = config.New()
}

func Pact(t *testing.T, pactDir string, provider string) *dsl.Pact {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skipf("We don't have pact on Windows in CI/CD")
	}
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
