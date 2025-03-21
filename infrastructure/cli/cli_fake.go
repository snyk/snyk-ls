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
	"context"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type TestExecutor struct {
	ExecuteResponse []byte
	wasExecuted     bool
	ExecuteDuration time.Duration
	startedScans    int
	finishedScans   int
	counterLock     sync.RWMutex
	cmd             []string
	logger          *zerolog.Logger
}

func NewTestExecutor() *TestExecutor {
	return &TestExecutor{ExecuteResponse: []byte("{}"), logger: config.CurrentConfig().Logger()}
}

func NewTestExecutorWithResponse(executeResponse string) *TestExecutor {
	return &TestExecutor{ExecuteResponse: []byte(executeResponse), logger: config.CurrentConfig().Logger()}
}

func NewTestExecutorWithResponseFromFile(executeResponsePath string, logger *zerolog.Logger) *TestExecutor {
	fileContent, err := os.ReadFile(executeResponsePath)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to read test response file.")
	}
	return &TestExecutor{ExecuteResponse: fileContent, logger: logger}
}

func (t *TestExecutor) GetStartedScans() int {
	t.counterLock.RLock()
	defer t.counterLock.RUnlock()
	return t.startedScans
}

func (t *TestExecutor) GetFinishedScans() int {
	t.counterLock.RLock()
	defer t.counterLock.RUnlock()
	return t.finishedScans
}

func (t *TestExecutor) GetCommand() []string {
	return t.cmd
}

func (t *TestExecutor) Execute(ctx context.Context, cmd []string, workingDir types.FilePath) (resp []byte, err error) {
	err = ctx.Err()
	if err != nil { // Checking for ctx cancellation before faking CLI execution
		return resp, err
	}

	// Increment the number of started scans after checking for ctx cancellation to simulate a running CLI
	t.counterLock.Lock()
	t.cmd = cmd
	t.startedScans++
	t.counterLock.Unlock()

	select {
	case <-time.After(t.ExecuteDuration):
		t.logger.Debug().Msg("Dummy CLI Execution time finished")
		// Indicate that the scan has finished and return the ExecuteResponse
		t.wasExecuted = true
		t.counterLock.Lock()
		t.finishedScans++
		t.counterLock.Unlock()
		return t.ExecuteResponse, err
	case <-ctx.Done():
		t.logger.Debug().Msg("Dummy CLI Execution canceled")
		return resp, ctx.Err()
	}
}

func (t *TestExecutor) ExpandParametersFromConfig(_ []string) []string {
	return nil
}

func (t *TestExecutor) HandleErrors(_ context.Context, _ string) (fail bool) {
	return false
}

func (t *TestExecutor) WasExecuted() bool {
	return t.wasExecuted
}
