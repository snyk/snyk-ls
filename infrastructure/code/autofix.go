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
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
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

func (s *SnykCodeHTTPClient) GetAutoFixDiffs(ctx context.Context, baseDir string, options AutofixOptions) (unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion) {
	logger := config.CurrentConfig().Logger().With().Str("method", "GetAutoFixDiffs").Logger()

	response, err := s.RunAutofix(ctx, options)
	if err != nil || response.Status == failed.message {
		logger.Err(err).Msg("error getting autofix suggestions")
		return unifiedDiffSuggestions
	}

	return response.toUnifiedDiffSuggestions(baseDir, options.filePath)
}

func (sc *Scanner) GetAutoFixDiffs(ctx context.Context, baseDir string, filePath string, issue snyk.Issue) (unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion) {
	codeClient := sc.BundleUploader.SnykCode
	bundleHash, found := sc.BundleHashes[baseDir]
	if !found {
		return unifiedDiffSuggestions
	}

	options := AutofixOptions{
		bundleHash: bundleHash,
		shardKey:   getShardKey(baseDir, config.CurrentConfig().Token()),
		filePath:   filePath,
		issue:      issue,
	}
	return codeClient.GetAutoFixDiffs(ctx, baseDir, options)
}
