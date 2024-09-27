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

func (s *SnykCodeHTTPClient) GetAutoFixDiffs(ctx context.Context, baseDir string, options AutofixOptions) (
	unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion,
	status AutofixStatus,
	err error,
) {
	method := "GetAutoFixDiffs"
	logger := config.CurrentConfig().Logger().With().Str("method", method).Logger()
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	var response AutofixResponse
	requestId, err := performance2.GetTraceId(ctx)
	if err != nil {
		logger.Err(err).Msg(failedToObtainRequestIdString + err.Error())
		return unifiedDiffSuggestions, status, err
	}

	logger.Info().Str("requestId", requestId).Msg("Started obtaining autofix diffs")
	defer logger.Info().Str("requestId", requestId).Msg("Finished obtaining autofix diffs")

	response, err = s.RunAutofix(span.Context(), options)
	if err != nil {
		return unifiedDiffSuggestions, status, err
	}

	logger.Debug().Msgf("Status: %s", response.Status)

	if response.Status == failed.message {
		logger.Err(err).Str("responseStatus", response.Status).Msg("autofix failed")
		return nil, failed, err
	}

	if response.Status == "" {
		logger.Err(err).Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return nil, failed, err
	}

	status = AutofixStatus{message: response.Status}
	if response.Status != completeStatus {
		return nil, status, nil
	}

	logger.Debug().Msgf("Running toUnifiedDiffSuggestions")
	return response.toUnifiedDiffSuggestions(baseDir, options.filePath), AutofixStatus{message: response.Status}, err
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
			suggestions, fixStatus, err := codeClient.GetAutoFixDiffs(span.Context(), baseDir, options)
			if err != nil {
				logger.Err(err).Msg("Error getting autofix suggestions")
				return suggestions, err
			} else if fixStatus.message == completeStatus {
				if  len(suggestions) > 0 {
					return suggestions, nil
				} else {
					logger.Debug().Msg("AI fix returned successfully but no good fix could be computed.")
					return suggestions, nil
				}
			}
		}
	}
}
