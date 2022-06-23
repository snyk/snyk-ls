package code

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
	"github.com/snyk/snyk-ls/lsp"
)

type Bundle struct {
	SnykCode      SnykCodeClient
	BundleHash    string
	UploadBatches []*UploadBatch
	instrumentor  performance.Instrumentor
	requestId     string
	missingFiles  []string
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
	rootPath string,
	output func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers),
) {
	defer log.Debug().Str("method", "FetchDiagnosticsData").Msg("done.")
	log.Debug().Str("method", "FetchDiagnosticsData").Msg("started.")
	b.retrieveAnalysis(ctx, rootPath, output)
}

func (b *Bundle) retrieveAnalysis(
	ctx context.Context,
	rootPath string,
	output func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers),
) {
	if b.BundleHash == "" {
		log.Warn().Str("method", "retrieveAnalysis").Str("rootPath", rootPath).Msg("bundle hash is empty")
		return
	}

	p := progress.NewTracker(false)
	p.Begin("Snyk Code analysis", "Retrieving results...")
	defer p.End("Analysis complete.")

	method := "code.retrieveAnalysis"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	analysisOptions := AnalysisOptions{
		bundleHash:   b.BundleHash,
		shardKey:     b.getShardKey(rootPath, config.CurrentConfig().Token()),
		limitToFiles: []sglsp.DocumentURI{},
		severity:     0,
	}

	for {
		start := time.Now()
		diags, hovers, status, err := b.SnykCode.RunAnalysis(s.Context(), analysisOptions)

		if err != nil {
			log.Error().Err(err).
				Str("method", "retrieveAnalysis").
				Str("requestId", b.requestId).
				Int("fileCount", len(b.UploadBatches)).
				Msg("error retrieving diagnostics...")
			//di.ErrorReporter().CaptureError(err) FIXME import cycle
			return
		}

		if status.message == "COMPLETE" {
			for filePath, diagnostics := range diags {
				log.Trace().Str("method", "retrieveAnalysis").Str("requestId", b.requestId).
					Str("path", filePath).
					Msg("sending diagnostics...")

				if len(diagnostics) > 0 {
					documentURI := uri.PathToUri(filePath)
					output(
						map[string][]lsp.Diagnostic{filePath: diagnostics},
						[]hover.DocumentHovers{{Uri: documentURI, Hover: hovers[documentURI]}},
					)
				}
			}

			return
		}

		if time.Since(start) > config.CurrentConfig().SnykCodeAnalysisTimeout() {
			err = errors.New("analysis call timed out")
			log.Error().Err(err).Str("method", "retrieveAnalysis").Msg("timeout...")
			//di.ErrorReporter().CaptureError(err) // FIXME import cycle
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
