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
	fixHandler.explainCancelFunc = cancelFunc
	defer cancelFunc()
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
	endpoint, err := getExplainEndpoint(c, issue.GetContentRoot())
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to get explain endpoint for issue %s", issue.GetID())
		return
	}
	explanations, err := deepCodeLLMBinding.ExplainWithOptions(contextWithCancel, llm.ExplainOptions{RuleKey: issue.GetID(), Diffs: diffs, Endpoint: endpoint})
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

func getExplainEndpoint(c *config.Config, contentRoot types.FilePath) (*url.URL, error) {
	workspaceFolder := c.Workspace().GetFolderContaining(contentRoot)
	if workspaceFolder == nil {
		return nil, fmt.Errorf("no folder found for content root: %s", contentRoot)
	}
	org := c.FolderOrganization(workspaceFolder.Path())
	if org == "" {
		return nil, fmt.Errorf("no organization configured for folder: %s", workspaceFolder.Path())
	}
	endpoint, err := url.Parse(fmt.Sprintf("%s/rest/orgs/%s/explain-fix", c.SnykApi(), org))
	if err != nil {
		return nil, fmt.Errorf("failed to parse explain endpoint URL: %w", err)
	}
	queryParams := url.Values{}
	queryParams.Add("version", ExplainApiVersion)
	endpoint.RawQuery = queryParams.Encode()

	return endpoint, nil
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
	fixHandler.aiFixDiffState = aiResultState{status: state, result: suggestions, err: err}
	if callback != nil {
		callback()
	}
}

func (fixHandler *AiFixHandler) SetAutoTriggerAiFix(isEnabled bool) {
	fixHandler.autoTriggerAiFix = isEnabled
}

func (fixHandler *AiFixHandler) resetAiFixCacheIfDifferent(issue types.Issue) {
	if issue.GetAdditionalData().GetKey() == fixHandler.currentIssueId {
		return
	}

	fixHandler.aiFixDiffState = aiResultState{status: AiFixNotStarted}
	fixHandler.currentIssueId = issue.GetAdditionalData().GetKey()
	if fixHandler.explainCancelFunc != nil {
		fixHandler.explainCancelFunc()
	}
	fixHandler.explainCancelFunc = nil
}
