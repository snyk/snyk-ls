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

func (s *SnykCodeHTTPClient) GetAutofixDiffs(ctx context.Context, baseDir string, options AutofixOptions) (
	unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion,
	status AutofixStatus,
	err error,
) {
	method := "GetAutofixDiffs"
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)
	logger := config.CurrentConfig().Logger().With().Str("method", method).Logger()
	logger.Info().Msg("Started obtaining autofix diffs")
	defer logger.Info().Msg("Finished obtaining autofix diffs")

	autofixResponse, status, err := s.getAutofixResponse(ctx, options)
	if err != nil {
		return nil, status, err
	}
	return autofixResponse.toUnifiedDiffSuggestions(baseDir, options.filePath), status, err
}

func (s *SnykCodeHTTPClient) getAutofixResponse(ctx context.Context, options AutofixOptions) (autofixResponse AutofixResponse, status AutofixStatus, err error) {
	method := "getAutofixResponse"
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)
	logger := config.CurrentConfig().Logger().With().Str("method", method).Logger()

	requestId, err := performance2.GetTraceId(ctx)
	if err != nil {
		logger.Err(err).Msg(failedToObtainRequestIdString + err.Error())
		return autofixResponse, failed, err
	}
	logger.Info().Str("requestId", requestId).Msg("Started obtaining autofix Response")
	defer logger.Info().Str("requestId", requestId).Msg("Finished obtaining autofix Response")

	response, err := s.RunAutofix(span.Context(), options)
	if err != nil {
		return response, failed, err
	}

	logger.Debug().Msgf("Status: %s", response.Status)

	if response.Status == failed.message {
		logger.Error().Str("responseStatus", response.Status).Msg("autofix failed")
		return response, failed, errors.New("Autofix failed")
	}

	if response.Status == "" {
		logger.Error().Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return response, failed, errors.New("Unknown response status (empty)")
	}

	status = AutofixStatus{message: response.Status}
	if response.Status != completeStatus {
		return response, status, nil
	}

	return response, status, nil
}

func (sc *Scanner) GetAutofixDiffs(
	ctx context.Context,
	baseDir string,
	filePath string,
	issue snyk.Issue,
) (unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion, err error) {
	method := "GetAutofixDiffs"
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
			suggestions, fixStatus, autofixErr := codeClient.GetAutofixDiffs(span.Context(), baseDir, options)
			if autofixErr != nil {
				logger.Err(autofixErr).Msg("Error getting autofix suggestions")
				return nil, autofixErr
			} else if fixStatus.message == completeStatus {
				if len(suggestions) == 0 {
					logger.Info().Msg("AI fix returned successfully but no good fix could be computed.")
				}
				return suggestions, nil
			}
			// If err == nil and fixStatus.message != completeStatus, we will keep polling.
		}
	}
}
