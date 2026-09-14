/*
 * © 2025 Snyk Limited
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

package code

import (
	"sync"
	"testing"

	"github.com/snyk/code-client-go/llm"
	"github.com/stretchr/testify/assert"
)

func Test_AiFixHandler_ConcurrentReadDuringStateChange_NeverObservesTornState(t *testing.T) {
	handler := &AiFixHandler{aiFixDiffState: aiResultState{status: AiFixNotStarted}}
	successSuggestions := []llm.AutofixUnifiedDiffSuggestion{
		{FixId: "fix-1", UnifiedDiffsPerFile: map[string]string{"app.js": "diff"}},
	}

	const iterations = 2000
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			handler.SetAiFixDiffState(AiFixNotStarted, nil, nil, nil)
			handler.SetAiFixDiffState(AiFixSuccess, successSuggestions, nil, nil)
		}
	}()
	defer wg.Wait()

	for i := 0; i < iterations; i++ {
		status, result, _ := handler.GetAiFixDiffSnapshot()
		switch status {
		case AiFixSuccess:
			assert.NotEmptyf(t, result, "iteration %d: status SUCCESS but result was empty", i)
		case AiFixNotStarted:
			assert.Emptyf(t, result, "iteration %d: status NOT_STARTED but result was non-empty", i)
		case AiFixInProgress, AiFixError:
			// not exercised by this test's writer goroutine
		}
	}
}
