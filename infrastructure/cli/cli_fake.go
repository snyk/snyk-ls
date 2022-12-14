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

func (t *TestExecutor) Execute(ctx context.Context, _ []string, _ string) (resp []byte, err error) {
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

func (t *TestExecutor) ExpandParametersFromConfig(_ []string) []string {
	return nil
}

func (t *TestExecutor) HandleErrors(_ context.Context, _ string) (fail bool) {
	return false
}

func (t *TestExecutor) WasExecuted() bool {
	return t.wasExecuted
}
