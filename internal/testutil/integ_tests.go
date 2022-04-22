package testutil

import (
	"os"
	"testing"

	"github.com/snyk/snyk-ls/internal/progress"
)

const integTestEnvVar = "INTEG_TESTS"

func IntegTest(t *testing.T) {
	t.Helper()
	if os.Getenv(integTestEnvVar) == "" {
		t.Logf("%s is not set", integTestEnvVar)
		t.SkipNow()
	}
}

func CreateDummyProgressListener(t *testing.T) {
	t.Helper()
	var dummyProgressStopChannel chan bool = make(chan bool, 1)

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
