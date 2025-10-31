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
	"net/url"
	"sync"
	"time"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/llm"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type AiFixHandler struct {
	aiFixDiffState    aiResultState
	currentIssueId    string
	explainCancelFunc context.CancelFunc
	autoTriggerAiFix  bool
	mu                sync.RWMutex
}

type AiStatus string

const (
	AiFixNotStarted  AiStatus = "NOT_STARTED"
	AiFixInProgress  AiStatus = "IN_PROGRESS"
	AiFixSuccess     AiStatus = "SUCCESS"
	AiFixError       AiStatus = "ERROR"
	shouldRunExplain          = true
)
const (
	ExplainApiVersion string = "2024-10-15"
)

type aiResultState struct {
	status AiStatus
	err    error
	result []llm.AutofixUnifiedDiffSuggestion
}

const explainTimeout = 5 * time.Minute

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

func (fixHandler *AiFixHandler) EnrichWithExplain(ctx context.Context, c *config.Config, issue types.Issue, suggestions []llm.AutofixUnifiedDiffSuggestion) {
	if !shouldRunExplain {
		return
	}
	logger := c.Logger().With().Str("method", "EnrichWithExplain").Logger()
	if ctx.Err() != nil {
		logger.Debug().Msgf("EnrichWithExplain context canceled")
		return
	}
	contextWithCancel, cancelFunc := context.WithTimeout(ctx, explainTimeout)
	defer cancelFunc()

	fixHandler.mu.Lock()
	fixHandler.explainCancelFunc = cancelFunc
	fixHandler.mu.Unlock()

	if len(suggestions) == 0 {
		return
	}
	var diffs []string
	diffs = getDiffListFromSuggestions(suggestions, diffs)
	deepCodeLLMBinding := llm.NewDeepcodeLLMBinding(
		llm.WithLogger(c.Logger()),
		llm.WithOutputFormat(llm.HTML),
		llm.WithHTTPClient(func() codeClientHTTP.HTTPClient {
			return c.Engine().GetNetworkAccess().GetHttpClient()
		}),
	)
	explanations, err := deepCodeLLMBinding.ExplainWithOptions(contextWithCancel, llm.ExplainOptions{RuleKey: issue.GetID(), Diffs: diffs, Endpoint: getExplainEndpoint(c, issue.GetContentRoot())})
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to explain with explain for issue %s", issue.GetID())
		return
	}
	for i, diff := range diffs {
		if i >= len(explanations) {
			logger.Debug().Msgf("Failed to get explanation for issue with diff index %v diff %s", i, diff)
			break
		}
		suggestions[i].Explanation = explanations[i]
	}
}

func getExplainEndpoint(c *config.Config, folder types.FilePath) *url.URL {
	org := c.FolderOrganization(folder)
	endpoint, err := url.Parse(fmt.Sprintf("%s/rest/orgs/%s/explain-fix", c.SnykApi(), org))
	if err != nil {
		return &url.URL{}
	}
	queryParams := url.Values{}
	queryParams.Add("version", ExplainApiVersion)
	endpoint.RawQuery = queryParams.Encode()

	return endpoint
}

func getDiffListFromSuggestions(suggestions []llm.AutofixUnifiedDiffSuggestion, diffs []string) []string {
	// Suggestion diffs may be coming from different files
	for i := range suggestions {
		diff := ""
		for _, v := range suggestions[i].UnifiedDiffsPerFile {
			diff += v
		}
		diffs = append(diffs, diff)
	}
	return diffs
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

	// Make a copy of the explain cancel function to avoid race conditions
	localExplainCancelFunc := fixHandler.explainCancelFunc
	fixHandler.explainCancelFunc = nil
	fixHandler.mu.Unlock()

	if localExplainCancelFunc != nil {
		localExplainCancelFunc()
	}
}
