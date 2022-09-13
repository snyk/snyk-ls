package cli

import (
	"context"
	"sync"
	"time"
)

type TestExecutor struct {
	ExecuteResponse string
	wasExecuted     bool
	ExecuteDuration time.Duration
	runningScans    int
	maxRunningScans int
	counterLock     sync.Mutex
}

func NewTestExecutor() *TestExecutor {
	return &TestExecutor{ExecuteResponse: "{}"}
}

func (t *TestExecutor) GetRunningScans() int    { return t.runningScans }
func (t *TestExecutor) GetMaxRunningScans() int { return t.maxRunningScans }

func (t *TestExecutor) Execute(ctx context.Context, cmd []string, workingDir string) (resp []byte, err error) {
	err = ctx.Err()
	if err != nil { // When the operation is cancelled via the context, return empty results and don't set "wasExecuted"
		return resp, err
	}

	t.counterLock.Lock()
	t.runningScans++
	if t.runningScans > t.maxRunningScans {
		t.maxRunningScans = t.runningScans
	}
	t.counterLock.Unlock()

	if t.ExecuteDuration > 0 {
		time.Sleep(t.ExecuteDuration)
	}

	t.wasExecuted = true
	return []byte(t.ExecuteResponse), err
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
