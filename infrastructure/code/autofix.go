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
	"time"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	performance2 "github.com/snyk/snyk-ls/internal/observability/performance"
)

// AutofixUnifiedDiffSuggestion represents the diff between the original and the fixed source code.
type AutofixUnifiedDiffSuggestion struct {
	FixId               string            `json:"fixId"`
	UnifiedDiffsPerFile map[string]string `json:"unifiedDiffsPerFile"`
}

func (a AutofixUnifiedDiffSuggestion) String() string {
	return fmt.Sprintf("FixId: %s, UnifiedDiffsPerFile: %v", a.FixId, a.UnifiedDiffsPerFile)
}

func (a AutofixUnifiedDiffSuggestion) GetUnifiedDiffForFile(filePath string) string {
	return a.UnifiedDiffsPerFile[filePath]
}

func (s *SnykCodeHTTPClient) GetAutoFixDiffs(ctx context.Context, baseDir string, options AutofixOptions) (unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion, err error) {
	method := "GetAutoFixDiffs"
	logger := config.CurrentConfig().Logger().With().Str("method", method).Logger()
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	var response AutofixResponse
	requestId, err := performance2.GetTraceId(ctx)
	if err != nil {
		logger.Err(err).Msg(failedToObtainRequestIdString + err.Error())
		return unifiedDiffSuggestions, err
	}

	logger.Info().Str("requestId", requestId).Msg("Started obtaining autofix diffs")
	defer logger.Info().Str("requestId", requestId).Msg("Finished obtaining autofix diffs")

	response, err = s.RunAutofix(span.Context(), options)
	// todo(berkay): burada fixlenebilir. burasi unufied diff flow, code action flow nasil?
	if err != nil || response.Status == failed.message {
		logger.Err(err).Msg("error getting autofix suggestions")
		return unifiedDiffSuggestions, err
	}

	return response.toUnifiedDiffSuggestions(baseDir, options.filePath), err
}

func (sc *Scanner) GetAutoFixDiffs(
	ctx context.Context,
	baseDir string,
	filePath string,
	issue snyk.Issue,
) (unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion, err error) {
	method := "GetAutoFixDiffs"
	logger := config.CurrentConfig().Logger().With().Str("method", method).Logger()
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, method)
	defer sc.BundleUploader.instrumentor.Finish(span)

	codeClient := sc.BundleUploader.SnykCode
	sc.bundleHashesMutex.RLock()
	bundleHash, found := sc.bundleHashes[baseDir]
	sc.bundleHashesMutex.RUnlock()
	if !found {
		return unifiedDiffSuggestions, fmt.Errorf("bundle hash not found for baseDir: %s", baseDir)
	}

	encodedNormalizedPath, err := ToEncodedNormalizedPath(baseDir, filePath)
	if err != nil {
		return unifiedDiffSuggestions, err
	}
	options := AutofixOptions{
		bundleHash: bundleHash,
		shardKey:   getShardKey(baseDir, config.CurrentConfig().Token()),
		filePath:   encodedNormalizedPath,
		issue:      issue,
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
			suggestions, err := codeClient.GetAutoFixDiffs(span.Context(), baseDir, options)
			if err != nil {
				logger.Err(err).Msg("Error getting autofix suggestions")
				return nil, err
			}
			// todo(berkay): Change to status check
			if len(suggestions) > 0 {
				return suggestions, err
			}
		}
	}
}
