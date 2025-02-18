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
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/snyk/code-client-go/llm"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type AiFixHandler struct {
	aiFixDiffState    aiResultState
	currentIssueId    string
	deepCodeBinding   llm.DeepCodeLLMBinding
	explainCancelFunc context.CancelFunc
	autoTriggerAiFix  bool
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
	result []AutofixUnifiedDiffSuggestion
}

const explainTimeout = 5 * time.Minute

func (fixHandler *AiFixHandler) GetCurrentIssueId() string {
	return fixHandler.currentIssueId
}

func (fixHandler *AiFixHandler) GetResults(fixId string) (filePath string, diff string, err error) {
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

func (fixHandler *AiFixHandler) EnrichWithExplain(ctx context.Context, c *config.Config, issue snyk.Issue, suggestions []AutofixUnifiedDiffSuggestion) {
	logger := c.Logger().With().Str("method", "EnrichWithExplain").Logger()
	if ctx.Err() != nil {
		logger.Debug().Msgf("EnrichWithExplain context canceled")
		return
	}
	contextWithCancel, cancelFunc := context.WithTimeout(ctx, explainTimeout)
	fixHandler.explainCancelFunc = cancelFunc
	defer cancelFunc()
	if len(suggestions) == 0 {
		return
	}
	var wg sync.WaitGroup
	for i := range suggestions {
		diff := ""
		for _, v := range suggestions[i].UnifiedDiffsPerFile {
			diff += v
		}
		wg.Add(1)
		go func() {
			response, err := fixHandler.deepCodeBinding.ExplainWithOptions(contextWithCancel, llm.ExplainOptions{RuleKey: issue.ID, Diff: diff})
			wg.Done()
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to explain with explain for issue %s", issue.AdditionalData.GetKey())
				return
			}
			suggestions[i].Explanation = response
		}()
	}
	wg.Wait()
}

func (fixHandler *AiFixHandler) SetAiFixDiffState(state AiStatus, suggestions []AutofixUnifiedDiffSuggestion, err error, callback func()) {
	fixHandler.aiFixDiffState = aiResultState{status: state, result: suggestions, err: err}
	if callback != nil {
		callback()
	}
}

func (fixHandler *AiFixHandler) SetAutoTriggerAiFix(isEnabled bool) {
	fixHandler.autoTriggerAiFix = isEnabled
}

func (fixHandler *AiFixHandler) resetAiFixCacheIfDifferent(issue snyk.Issue) {
	if issue.AdditionalData.GetKey() == fixHandler.currentIssueId {
		return
	}

	fixHandler.aiFixDiffState = aiResultState{status: AiFixNotStarted}
	fixHandler.currentIssueId = issue.AdditionalData.GetKey()
	if fixHandler.explainCancelFunc != nil {
		fixHandler.explainCancelFunc()
	}
	fixHandler.explainCancelFunc = nil
	fixHandler.autoTriggerAiFix = false
}
