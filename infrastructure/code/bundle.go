/*
 * © 2022-2024 Snyk Limited
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
	"strings"

	"github.com/rs/zerolog"

	codeClientObservability "github.com/snyk/code-client-go/observability"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

type Bundle struct {
	SnykCode      SnykCodeClient
	BundleHash    string
	UploadBatches []*UploadBatch
	Files         map[types.FilePath]BundleFile
	instrumentor  codeClientObservability.Instrumentor
	errorReporter codeClientObservability.ErrorReporter
	requestId     string
	missingFiles  []types.FilePath
	limitToFiles  []types.FilePath
	rootPath      types.FilePath
	issueEnhancer IssueEnhancer
	logger        *zerolog.Logger
}

func (b *Bundle) Upload(ctx context.Context, uploadBatch *UploadBatch) error {
	err := b.extendBundle(ctx, uploadBatch)
	if err != nil {
		return err
	}
	b.UploadBatches = append(b.UploadBatches, uploadBatch)
	return nil
}

func (b *Bundle) extendBundle(ctx context.Context, uploadBatch *UploadBatch) error {
	var removeFiles []types.FilePath
	var err error
	if uploadBatch.hasContent() {
		b.BundleHash, b.missingFiles, err = b.SnykCode.ExtendBundle(ctx, b.BundleHash, uploadBatch.documents,
			removeFiles)
		b.logger.Debug().Str("requestId", b.requestId).Interface(
			"missingFiles",
			b.missingFiles,
		).Msg("extended bundle on backend")
	}

	return err
}

func getIssueLangAndRuleId(issue types.Issue) (string, string, bool) {
	logger := config.CurrentConfig().Logger().With().Str("method", "getIssueLangAndRuleId").Logger()
	issueData, ok := issue.GetAdditionalData().(snyk.CodeIssueData)
	if !ok {
		logger.Trace().Str("file", string(issue.GetAffectedFilePath())).Int("line", issue.GetRange().Start.Line).Msg("Can't access issue data")
		return "", "", false
	}
	// NOTE(alex.gronskiy): we tend to receive either `<lang>/<ruleID>` or `<lang>/<ruleID>/test` (the
	// latter is returned when a file is considered a "test" one, using complex heuristics on Suggest).
	// For our purposes, we need to know language and rule ID regardless whether this is test file or not.
	ruleIdSplit := strings.Split(issueData.RuleId, "/")
	if len(ruleIdSplit) == 2 || len(ruleIdSplit) == 3 {
		// 0: lang, 1: ruleId
		return ruleIdSplit[0], ruleIdSplit[1], true
	}

	logger.Trace().Str("file", string(issue.GetAffectedFilePath())).Int("line", issue.GetRange().Start.Line).Msg("Issue data does not contain RuleID")
	return "", "", false
}
