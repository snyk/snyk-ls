/*
 * © 2024 Snyk Limited
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
	"errors"
	"fmt"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/llm"
	"time"

	performance2 "github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/types"
)

// AutofixUnifiedDiffSuggestion represents the diff between the original and the fixed source code.
type AutofixUnifiedDiffSuggestion struct {
	FixId               string            `json:"fixId"`
	UnifiedDiffsPerFile map[string]string `json:"unifiedDiffsPerFile"`
	FullTextPerFile     map[string]string `json:"fullTextPerFile"`
	Explanation         string            `json:"explanation"`
}

func (a AutofixUnifiedDiffSuggestion) String() string {
	return fmt.Sprintf("FixId: %s, UnifiedDiffsPerFile: %v", a.FixId, a.UnifiedDiffsPerFile)
}

func (a AutofixUnifiedDiffSuggestion) GetUnifiedDiffForFile(filePath string) string {
	return a.UnifiedDiffsPerFile[filePath]
}

func (sc *Scanner) GetAutofixDiffs(ctx context.Context, baseDir types.FilePath, filePath types.FilePath, issue types.Issue) (unifiedDiffSuggestions []llm.AutofixUnifiedDiffSuggestion, err error) {
	method := "GetAutofixDiffs"
	logger := sc.C.Logger().With().Str("method", method).Logger()
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, method)
	defer sc.BundleUploader.instrumentor.Finish(span)

	sc.bundleHashesMutex.RLock()
	bundleHash, found := sc.bundleHashes[baseDir]
	sc.bundleHashesMutex.RUnlock()
	if !found {
		return unifiedDiffSuggestions, fmt.Errorf("bundle hash not found for baseDir: %s", baseDir)
	}

	encodedNormalizedPath, err := toEncodedNormalizedPath(baseDir, filePath)
	if err != nil {
		return unifiedDiffSuggestions, err
	}

	// ticker sends a trigger every second to its channel
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	// timeoutTimer sends a trigger after 2 minutes to its channel
	timeoutTimer := time.NewTimer(2 * time.Minute)
	defer timeoutTimer.Stop()
	for {
		select {
		case <-timeoutTimer.C:
			const msg = "Timeout waiting for code fix diffs."
			logger.Error().Msg(msg)
			return nil, errors.New(msg)
		case <-ticker.C:
			deepCodeLLMBinding := llm.NewDeepcodeLLMBinding(
				llm.WithLogger(sc.C.Logger()),
				llm.WithOutputFormat(llm.HTML),
				llm.WithHTTPClient(func() codeClientHTTP.HTTPClient {
					return sc.C.Engine().GetNetworkAccess().GetHttpClient()
				}),
			)

			requestId, traceErr := performance2.GetTraceId(ctx)
			if traceErr != nil {
				return nil, err
			}

			_, ruleId, ok := getIssueLangAndRuleId(issue)
			if !ok {
				return nil, SnykAutofixFailedError{Msg: "Issue's ruleID does not follow <lang>/<ruleKey> format"}
			}

			options := llm.AutofixOptions{
				BundleHash:         bundleHash,
				ShardKey:           getShardKey(baseDir, sc.C.Token()),
				BaseDir:            string(baseDir),
				FilePath:           string(encodedNormalizedPath),
				CodeRequestContext: newCodeRequestContext().toAutofixCodeRequestContext(),
				LineNum:            issue.GetRange().Start.Line + 1,
				RuleID:             ruleId,
				Endpoint:           getAutofixEndpoint(sc.C),
				IdeExtensionDetails: llm.AutofixIdeExtensionDetails{
					IdeName:          sc.C.IdeName(),
					IdeVersion:       sc.C.IdeVersion(),
					ExtensionName:    sc.C.IntegrationName(),
					ExtensionVersion: sc.C.IntegrationVersion(),
				},
			}

			suggestions, fixStatus, autofixErr := deepCodeLLMBinding.GetAutofixDiffs(span.Context(), requestId, options)
			if autofixErr != nil {
				logger.Err(autofixErr).Msg("Error getting autofix suggestions")
				return nil, autofixErr
			} else if fixStatus.Message == completeStatus {
				if len(suggestions) == 0 {
					logger.Info().Msg("AI fix returned successfully but no good fix could be computed.")
				}
				return suggestions, nil
			}
			// If err == nil and fixStatus.message != completeStatus, we will keep polling.
		}
	}
}

func toEncodedNormalizedPath(rootPath types.FilePath, filePath types.FilePath) (types.FilePath, error) {
	relativePath, err := ToRelativeUnixPath(rootPath, filePath)
	if err != nil {
		// couldn't make it relative, so it's already relative
		relativePath = filePath
	}

	encodedRelativePath := EncodePath(relativePath)
	return encodedRelativePath, nil
}
