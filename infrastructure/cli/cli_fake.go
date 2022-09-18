package cli

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type TestExecutor struct {
	ExecuteResponse string
	wasExecuted     bool
	ExecuteDuration time.Duration
	finishedScans   int
	counterLock     sync.Mutex
}

func NewTestExecutor() *TestExecutor {
	return &TestExecutor{ExecuteResponse: "{}"}
}

func (t *TestExecutor) GetFinishedScans() int { return t.finishedScans }

func (t *TestExecutor) Execute(ctx context.Context, cmd []string, workingDir string) (resp []byte, err error) {
	err = ctx.Err()
	if err != nil { // Checking for ctx cancellation before faking CLI execution
		return resp, err
	}

	select {
	case <-time.After(t.ExecuteDuration):
		log.Debug().Msg("Dummy CLI Execution time finished")
		// Indicate that the scan has finished and return the ExecuteResponse
		t.wasExecuted = true
		t.counterLock.Lock()
		t.finishedScans++
		t.counterLock.Unlock()
		return []byte(t.ExecuteResponse), err
	case <-ctx.Done():
		log.Debug().Msg("Dummy CLI Execution cancelled")
		return resp, ctx.Err()
	}
}

func (t *TestExecutor) ExpandParametersFromConfig(base []string) []string {
	return nil
}

func (t *TestExecutor) HandleErrors(ctx context.Context, output string) (fail bool) {
	return false
}

func (t *TestExecutor) WasExecuted() bool {
	return t.wasExecuted
}
