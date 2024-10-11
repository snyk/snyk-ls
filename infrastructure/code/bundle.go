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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	codeClientObservability "github.com/snyk/code-client-go/observability"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/progress"
)

type Bundle struct {
	SnykCode      SnykCodeClient
	BundleHash    string
	UploadBatches []*UploadBatch
	Files         map[string]BundleFile
	instrumentor  codeClientObservability.Instrumentor
	errorReporter codeClientObservability.ErrorReporter
	requestId     string
	missingFiles  []string
	limitToFiles  []string
	rootPath      string
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
	var removeFiles []string
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

func (b *Bundle) FetchDiagnosticsData(ctx context.Context, t *progress.Tracker) ([]snyk.Issue, error) {
	defer b.logger.Debug().Str("method", "FetchDiagnosticsData").Msg("done.")
	b.logger.Debug().Str("method", "FetchDiagnosticsData").Msg("started.")
	return b.retrieveAnalysis(ctx, t)
}

func getIssueLangAndRuleId(issue snyk.Issue) (string, string, bool) {
	logger := config.CurrentConfig().Logger().With().Str("method", "getIssueLangAndRuleId").Logger()
	issueData, ok := issue.AdditionalData.(snyk.CodeIssueData)
	if !ok {
		logger.Trace().Str("file", issue.AffectedFilePath).Int("line", issue.Range.Start.Line).Msg("Can't access issue data")
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

	logger.Trace().Str("file", issue.AffectedFilePath).Int("line", issue.Range.Start.Line).Msg("Issue data does not contain RuleID")
	return "", "", false
}

func (b *Bundle) retrieveAnalysis(ctx context.Context, t *progress.Tracker) ([]snyk.Issue, error) {
	logger := b.logger.With().Str("method", "retrieveAnalysis").Str("requestId", b.requestId).Logger()

	if b.BundleHash == "" {
		logger.Warn().Str("rootPath", b.rootPath).Msg("bundle hash is empty")
		return []snyk.Issue{}, nil
	}

	method := "code.retrieveAnalysis"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	t.ReportWithMessage(40, "Snyk Code analysis for "+b.rootPath+", Retrieving results...")

	c := config.CurrentConfig()
	analysisOptions := AnalysisOptions{
		bundleHash:   b.BundleHash,
		shardKey:     getShardKey(b.rootPath, c.Token()),
		limitToFiles: b.limitToFiles,
		severity:     0,
	}

	logger.Trace().Str("rootPath", b.rootPath).Send()
	logger.Trace().Int("fileCount", len(b.Files)).Any("fileHashes", b.Files).Send()
	logger.Trace().Any("missingFiles", b.missingFiles).Send()
	logger.Trace().Any("limitToFiles", b.limitToFiles).Send()
	logger.Trace().Any("uploadBatches", b.UploadBatches).Send()

	start := time.Now()
	for {
		if ctx.Err() != nil || t.IsCanceled() { // Cancellation requested
			progress.Cancel(t.GetToken())
			return []snyk.Issue{}, nil
		}
		issues, status, err := b.SnykCode.RunAnalysis(s.Context(), analysisOptions, b.rootPath)

		if err != nil {
			logger.Error().Err(err).
				Int("fileCount", len(b.UploadBatches)).
				Msg("error retrieving diagnostics...")
			b.errorReporter.CaptureError(err, codeClientObservability.ErrorReporterOptions{ErrorDiagnosticPath: b.rootPath})
			t.ReportWithMessage(90, fmt.Sprintf("Analysis failed: %v", err))
			return []snyk.Issue{}, err
		}

		if status.message == completeStatus {
			logger.Trace().Msg("sending diagnostics...")
			t.ReportWithMessage(90, "Analysis complete.")

			b.issueEnhancer.addIssueActions(ctx, issues, b.BundleHash)

			return issues, nil
		} else if status.message == "ANALYZING" {
			logger.Trace().Msg("\"Analyzing\" message received, sending In-Progress message to client")
		}

		if time.Since(start) > c.SnykCodeAnalysisTimeout() {
			err := errors.New("analysis call timed out")
			b.logger.Error().Err(err).Msg("timeout...")
			b.errorReporter.CaptureError(err, codeClientObservability.ErrorReporterOptions{ErrorDiagnosticPath: b.rootPath})
			t.ReportWithMessage(90, "Snyk Code Analysis timed out")
			return []snyk.Issue{}, err
		}
		time.Sleep(1 * time.Second)
		t.Report(status.percentage)
	}
}
