/*
 * © 2022 Snyk Limited All rights reserved.
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

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/util"
)

type Bundle struct {
	SnykCode      SnykCodeClient
	BundleHash    string
	UploadBatches []*UploadBatch
	Files         map[string]BundleFile
	instrumentor  performance.Instrumentor
	errorReporter error_reporting.ErrorReporter
	requestId     string
	missingFiles  []string
	limitToFiles  []string
	rootPath      string
	scanNotifier  snyk.ScanNotifier
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
		b.BundleHash, b.missingFiles, err = b.SnykCode.ExtendBundle(ctx, b.BundleHash, uploadBatch.documents, removeFiles)
		log.Debug().Str("requestId", b.requestId).Interface(
			"missingFiles",
			b.missingFiles,
		).Msg("extended bundle on backend")
	}

	return err
}

func (b *Bundle) FetchDiagnosticsData(
	ctx context.Context,
) ([]snyk.Issue, error) {
	defer log.Debug().Str("method", "FetchDiagnosticsData").Msg("done.")
	log.Debug().Str("method", "FetchDiagnosticsData").Msg("started.")
	return b.retrieveAnalysis(ctx)
}

func (b *Bundle) retrieveAnalysis(ctx context.Context) ([]snyk.Issue, error) {
	logger := log.With().Str("method", "retrieveAnalysis").Logger()

	if b.BundleHash == "" {
		logger.Warn().Str("rootPath", b.rootPath).Msg("bundle hash is empty")
		return []snyk.Issue{}, nil
	}

	p := progress.NewTracker(false)
	p.Begin("Snyk Code analysis for "+b.rootPath, "Retrieving results...")

	method := "code.retrieveAnalysis"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	analysisOptions := AnalysisOptions{
		bundleHash:   b.BundleHash,
		shardKey:     b.getShardKey(b.rootPath, config.CurrentConfig().Token()),
		limitToFiles: b.limitToFiles,
		severity:     0,
	}

	start := time.Now()
	for {
		if ctx.Err() != nil { // Cancellation requested
			return []snyk.Issue{}, nil
		}
		issues, status, err := b.SnykCode.RunAnalysis(s.Context(), analysisOptions)

		if err != nil {
			logger.Error().Err(err).
				Str("requestId", b.requestId).
				Int("fileCount", len(b.UploadBatches)).
				Msg("error retrieving diagnostics...")
			b.errorReporter.CaptureErrorAndReportAsIssue(b.rootPath, err)
			p.End(fmt.Sprintf("Analysis failed: %v", err))
			return []snyk.Issue{}, err
		}

		if status.message == "COMPLETE" {
			logger.Trace().Str("requestId", b.requestId).
				Msg("sending diagnostics...")
			p.End("Analysis complete.")

			// TODO(alex.gronskiy): this should be correctly changed after the codeactions/resolves are
			// finished. Currently, this will slow down propotionally to the amount of issues.
			for i, issue := range issues {
				issues[i] = b.enhanceWithAutofixSuggestionEdits(ctx, issue)
			}

			return issues, nil
		} else if status.message == "ANALYZING" {
			logger.Trace().Msg("\"Analyzing\" message received, sending In-Progress message to client")

			if time.Since(start) > config.CurrentConfig().SnykCodeAnalysisTimeout() {
				err := errors.New("analysis call timed out")
				log.Error().Err(err).Msg("timeout...")
				b.errorReporter.CaptureErrorAndReportAsIssue(b.rootPath, err)
				p.End("Snyk Code Analysis timed out")
				return []snyk.Issue{}, err
			}
			time.Sleep(1 * time.Second)
			p.Report(status.percentage)
		}
	}
}

func (b *Bundle) getShardKey(rootPath string, authToken string) string {
	if b.BundleHash != "" {
		return util.Hash([]byte(b.BundleHash))
	}
	if len(rootPath) > 0 {
		return util.Hash([]byte(rootPath))
	}
	if len(authToken) > 0 {
		return util.Hash([]byte(authToken))
	}

	return ""
}

// addAutofixSuggesitons possibly enhances the snyk code issue from the passed array
// with autofix suggestions
func (b *Bundle) enhanceWithAutofixSuggestionEdits(ctx context.Context, issue snyk.Issue) snyk.Issue {
	if !config.CurrentConfig().IsSnykAutofixEnabled() {
		// TODO(alex.gronskiy): logging
		return issue
	}

	method := "code.enhanceWithAutofixSuggestionEdits"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)
	const autofixTimeout = 30 * time.Second

	autofixOptions := AutofixOptions{
		bundleHash: b.BundleHash,
		shardKey:   b.getShardKey(b.rootPath, config.CurrentConfig().Token()),
		filePath:   issue.AffectedFilePath,
		issue:      issue,
	}

	// Start polling the autofix command
	autofixStart := time.Now()
	for {
		if time.Since(autofixStart) > autofixTimeout {
			err := errors.New("autofix call timed out")
			log.Error().Err(err).Str("method", "RunAutofix").Msg("timeout...")
			break
		}

		fixSuggestions, fixStatus, err := b.SnykCode.RunAutofix(s.Context(), autofixOptions)
		if err != nil {
			log.Error().
				Err(err).
				Str("method", method).
				Str("requestId", b.requestId).
				Str("stage", "requesting autofix").
				Msg("error requesting autofix")
			break
		}

		if fixStatus.message != "COMPLETE" {
			time.Sleep(1 * time.Second)
			continue
		}
		// Actual suggestions obtained
		if len(fixSuggestions) > 0 {
			// TODO(alex.gronskiy): currently, only the first ([0]) fix suggstion goes into the fix
			issue.CodeActions = append(issue.CodeActions, fixSuggestions[0].FixCodeAction)
		}
		break
	}
	return issue
}
