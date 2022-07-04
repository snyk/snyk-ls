package code

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

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
	instrumentor  performance.Instrumentor
	errorReporter error_reporting.ErrorReporter
	requestId     string
	missingFiles  []string
	rootPath      string
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
		log.Debug().Str("requestId", b.requestId).Interface("missingFiles", b.missingFiles).Msg("extended bundle on backend")
	}

	return err
}

func (b *Bundle) FetchDiagnosticsData(
	ctx context.Context,
) []snyk.Issue {
	defer log.Debug().Str("method", "FetchDiagnosticsData").Msg("done.")
	log.Debug().Str("method", "FetchDiagnosticsData").Msg("started.")
	return b.retrieveAnalysis(ctx)
}

func (b *Bundle) retrieveAnalysis(ctx context.Context) []snyk.Issue {
	if b.BundleHash == "" {
		log.Warn().Str("method", "retrieveAnalysis").Str("rootPath", b.rootPath).Msg("bundle hash is empty")
		return []snyk.Issue{}
	}

	p := progress.NewTracker(false)
	p.Begin("Snyk Code analysis for "+b.rootPath, "Retrieving results...")
	defer p.End("Analysis complete.")

	method := "code.retrieveAnalysis"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	analysisOptions := AnalysisOptions{
		bundleHash:   b.BundleHash,
		shardKey:     b.getShardKey(b.rootPath, config.CurrentConfig().Token()),
		limitToFiles: []sglsp.DocumentURI{}, //todo remove lsp dependencies
		severity:     0,
	}

	for {
		start := time.Now()
		issues, status, err := b.SnykCode.RunAnalysis(s.Context(), analysisOptions)

		if err != nil {
			log.Error().Err(err).
				Str("method", "retrieveAnalysis").
				Str("requestId", b.requestId).
				Int("fileCount", len(b.UploadBatches)).
				Msg("error retrieving diagnostics...")
			b.errorReporter.CaptureError(err)
			return []snyk.Issue{}
		}

		if status.message == "COMPLETE" {
			log.Trace().Str("method", "retrieveAnalysis").Str("requestId", b.requestId).
				Msg("sending diagnostics...")
			return issues
		}

		if time.Since(start) > config.CurrentConfig().SnykCodeAnalysisTimeout() {
			err := errors.New("analysis call timed out")
			log.Error().Err(err).Str("method", "retrieveAnalysis").Msg("timeout...")
			b.errorReporter.CaptureError(err)
			p.End("Snyk Code Analysis timed out")
			return []snyk.Issue{}
		}
		time.Sleep(1 * time.Second)
		p.Report(status.percentage)
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
