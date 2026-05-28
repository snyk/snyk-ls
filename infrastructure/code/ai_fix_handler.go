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
	"fmt"
	"sync"

	"github.com/snyk/code-client-go/llm"

	"github.com/snyk/snyk-ls/internal/types"
)

type AiFixHandler struct {
	aiFixDiffState   aiResultState
	currentIssueId   string
	autoTriggerAiFix bool
	mu               sync.RWMutex
}

type AiStatus string

const (
	AiFixNotStarted AiStatus = "NOT_STARTED"
	AiFixInProgress AiStatus = "IN_PROGRESS"
	AiFixSuccess    AiStatus = "SUCCESS"
	AiFixError      AiStatus = "ERROR"
)

type aiResultState struct {
	status AiStatus
	err    error
	result []llm.AutofixUnifiedDiffSuggestion
}

func (fixHandler *AiFixHandler) GetCurrentIssueId() string {
	fixHandler.mu.RLock()
	defer fixHandler.mu.RUnlock()
	return fixHandler.currentIssueId
}

func (fixHandler *AiFixHandler) GetResults(fixId string) (filePath string, diff string, err error) {
	fixHandler.mu.RLock()
	defer fixHandler.mu.RUnlock()

	for _, suggestion := range fixHandler.aiFixDiffState.result {
		if suggestion.FixId == fixId {
			for k, v := range suggestion.UnifiedDiffsPerFile {
				filePath = k
				diff += v
			}
			return filePath, diff, nil
		}
	}
	return "", "", fmt.Errorf("no suggestion found for fixId: %s", fixId)
}


func (fixHandler *AiFixHandler) SetAiFixDiffState(state AiStatus, suggestions []llm.AutofixUnifiedDiffSuggestion, err error, callback func()) {
	fixHandler.mu.Lock()
	fixHandler.aiFixDiffState = aiResultState{status: state, result: suggestions, err: err}
	fixHandler.mu.Unlock()

	if callback != nil {
		callback()
	}
}

func (fixHandler *AiFixHandler) GetAutoTriggerAiFix() bool {
	fixHandler.mu.RLock()
	defer fixHandler.mu.RUnlock()
	return fixHandler.autoTriggerAiFix
}

func (fixHandler *AiFixHandler) SetAutoTriggerAiFix(isEnabled bool) {
	fixHandler.mu.Lock()
	defer fixHandler.mu.Unlock()
	fixHandler.autoTriggerAiFix = isEnabled
}

func (fixHandler *AiFixHandler) GetAiFixDiffStatus() AiStatus {
	fixHandler.mu.RLock()
	defer fixHandler.mu.RUnlock()
	return fixHandler.aiFixDiffState.status
}

func (fixHandler *AiFixHandler) GetAiFixDiffError() error {
	fixHandler.mu.RLock()
	defer fixHandler.mu.RUnlock()
	return fixHandler.aiFixDiffState.err
}

func (fixHandler *AiFixHandler) GetAiFixDiffResult() []llm.AutofixUnifiedDiffSuggestion {
	fixHandler.mu.RLock()
	defer fixHandler.mu.RUnlock()
	return fixHandler.aiFixDiffState.result
}

func (fixHandler *AiFixHandler) resetAiFixCacheIfDifferent(issue types.Issue) {
	issueKey := issue.GetAdditionalData().GetKey()

	fixHandler.mu.RLock()
	isSameIssue := issueKey == fixHandler.currentIssueId
	fixHandler.mu.RUnlock()

	if isSameIssue {
		return
	}

	fixHandler.mu.Lock()
	fixHandler.aiFixDiffState = aiResultState{status: AiFixNotStarted}
	fixHandler.currentIssueId = issueKey
	fixHandler.mu.Unlock()
}
