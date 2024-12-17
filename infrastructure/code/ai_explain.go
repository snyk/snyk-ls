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





func (sc *Scanner) GetAIExplanation(
	ctx context.Context,
	baseDir string,
	filePath string,
	issue snyk.Issue,
) (explanation string, err error) {
	method := "GetAIExplanation"
	logger := config.CurrentConfig().Logger().With().Str("method", method).Logger()
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, method)
	defer sc.BundleUploader.instrumentor.Finish(span)

	codeClient := sc.BundleUploader.SnykCode
	sc.bundleHashesMutex.RLock()
	bundleHash, found := sc.bundleHashes[baseDir]
	sc.bundleHashesMutex.RUnlock()
	if !found {
		return explanation, fmt.Errorf("bundle hash not found for baseDir: %s", baseDir)
	}

	encodedNormalizedPath, err := ToEncodedNormalizedPath(baseDir, filePath)
	if err != nil {
		return explanation, err
	}

	options := ExplainOptions{
		bundleHash: bundleHash,
		shardKey: getShardKey(baseDir, config.CurrentConfig().Token()),
		filePath: encodedNormalizedPath,
		issue: issue,
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	// timeoutTimer sends a trigger after 2 minutes to its channel
	timeoutTimer := time.NewTimer(2 * time.Minute)
	defer timeoutTimer.Stop()
	for {
		select {
		case <-timeoutTimer.C:
			const msg = "Timeout waiting for explanation."
			logger.Error().Msg(msg)
			return "", errors.New(msg)
		case <-ticker.C:
			explanation, explainStatus, explanationErr := codeClient.GetAIExplanation(span.Context(), baseDir, options)
			if explanationErr != nil {
				logger.Err(explanationErr).Msg("Error getting explanation")
				return "", explanationErr
			} else if explainStatus == completeStatus {
				return explanation, nil
			}
			// If err == nil and fixStatus.message != completeStatus, we will keep polling.
		}
	}
}


func (s *SnykCodeHTTPClient) GetAIExplanation(ctx context.Context, basedir string, options ExplainOptions) (
	explanation string,
	status string,
	err error,
) {
	method := "GetAIExplanation"
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)
	logger := config.CurrentConfig().Logger().With().Str("method", method).Logger()
	logger.Info().Msg("Started obtaining AI explanation")
	defer logger.Info().Msg("Finished obtaining AI explanation")

	explainResponse, err := s.getExplainResponse(ctx, options)
	if err != nil {
		return "", status, err
	}
	return explainResponse.Explanation, "COMPLETED", nil
}

func (s *SnykCodeHTTPClient) getExplainResponse(ctx context.Context, options ExplainOptions) (explainResponse ExplainResponse, err error) {
	method := "getExplainResponse"

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)
	logger := config.CurrentConfig().Logger().With().Str("method", method).Logger()

	requestId, err := performance2.GetTraceId(ctx)
	if err != nil {
		logger.Err(err).Msg(failedToObtainRequestIdString + err.Error())
		return explainResponse, err
	}
	logger.Info().Str("requestId", requestId).Msg("Started obtaining explain Response")
	defer logger.Info().Str("requestId", requestId).Msg("Finished obtaining explain Response")

	response, err := s.RunExplain(span.Context(), options)
	if err != nil {
		return response, err
	}

	logger.Debug().Msgf("Status: %s", response.Status)

	if response.Status == "FAILED" {
		logger.Error().Str("responseStatus", response.Status).Msg("explain failed")
		return response, errors.New("Explain failed")
	}

	if response.Status == "" {
		logger.Error().Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return response, errors.New("Unknown response status (empty)")
	}

	if response.Status != completeStatus {
		return response, nil
	}

	return response, nil
}







