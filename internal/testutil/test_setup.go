package testutil

import (
	"os"
	"testing"

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

func CreateDummyProgressListener(t *testing.T) {
	t.Helper()
	var dummyProgressStopChannel = make(chan bool, 1)

	t.Cleanup(func() {
		dummyProgressStopChannel <- true
	})

	go func() {
		for {
			select {
			case <-progress.ProgressChannel:
				continue
			case <-dummyProgressStopChannel:
				return
			}
		}
	}()

}
