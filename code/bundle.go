package code

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/observability/instrumentation"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/util"
	lsp2 "github.com/snyk/snyk-ls/lsp"
)

type Bundle struct {
	SnykCode      SnykCodeClient
	BundleHash    string
	UploadBatches []*UploadBatch
	instrumentor  instrumentation.Instrumentor
}

func (b *Bundle) Upload(ctx context.Context, uploadBatch *UploadBatch) error {
	if len(b.UploadBatches) == 0 {
		err := b.createBundle(ctx, uploadBatch)
		if err != nil {
			return err
		}
	} else {
		err := b.extendBundle(ctx, uploadBatch)
		if err != nil {
			return err
		}
	}
	b.UploadBatches = append(b.UploadBatches, uploadBatch)
	return nil
}

func (b *Bundle) createBundle(ctx context.Context, uploadBatch *UploadBatch) error {
	var err error
	if uploadBatch.hasContent() {
		b.BundleHash, _, err = b.SnykCode.CreateBundle(ctx, uploadBatch.documents)
		log.Debug().Str("bundleHash", b.BundleHash).Msg("created uploadBatch on backend")
	}
	return err
}

func (b *Bundle) extendBundle(ctx context.Context, uploadBatch *UploadBatch) error {
	var removeFiles []lsp.DocumentURI
	var err error
	if uploadBatch.hasContent() {
		b.BundleHash, _, err = b.SnykCode.ExtendBundle(ctx, b.BundleHash, uploadBatch.documents, removeFiles)
		log.Trace().Str("bundleHash", b.BundleHash).Msg("extended bundle on backend")
	}

	return err
}

func (b *Bundle) FetchDiagnosticsData(
	ctx context.Context,
	rootPath string,
	wg *sync.WaitGroup,
	dChan chan lsp2.DiagnosticResult,
	hoverChan chan lsp2.Hover,
) {
	defer wg.Done()
	defer log.Debug().Str("method", "FetchDiagnosticsData").Msg("done.")
	log.Debug().Str("method", "FetchDiagnosticsData").Msg("started.")
	b.retrieveAnalysis(ctx, rootPath, dChan, hoverChan)
}

func (b *Bundle) retrieveAnalysis(
	ctx context.Context,
	rootPath string,
	dChan chan lsp2.DiagnosticResult,
	hoverChan chan lsp2.Hover,
) {
	if b.BundleHash == "" || len(b.UploadBatches) == 0 {
		log.Warn().Str("method", "retrieveAnalysis").Str("rootPath", rootPath).Msg("bundle hash is empty")
		return
	}

	p := progress.NewTracker(false)
	p.Begin("Snyk Code analysis", "Retrieving results...")
	defer p.End("Analysis complete.")

	method := "code.retrieveAnalysis"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	for {
		start := time.Now()
		diags, hovers, status, err := b.SnykCode.RunAnalysis(ctx,
			b.BundleHash,
			b.getShardKey(rootPath, config.CurrentConfig().Token()),
			[]lsp.DocumentURI{},
			0,
		)

		if err != nil {
			log.Error().Err(err).
				Str("method", "retrieveAnalysis").
				Str("bundleHash", b.BundleHash).
				Int("fileCount", len(b.UploadBatches)).
				Msg("error retrieving diagnostics...")
			dChan <- lsp2.DiagnosticResult{Err: err}
			return
		}

		if status.message == "COMPLETE" {
			for u, d := range diags {
				log.Trace().Str("method", "retrieveAnalysis").Str("bundleHash", b.BundleHash).
					Str("path", string(u)).
					Msg("sending diagnostics...")

				dChan <- lsp2.DiagnosticResult{
					Uri:         u,
					Diagnostics: d,
					Err:         err,
				}
			}
			sendHoversViaChan(hovers, hoverChan)
			return
		}

		if time.Since(start) > config.CurrentConfig().SnykCodeAnalysisTimeout() {
			err = errors.New("analysis call timed out")
			log.Error().Err(err).Str("method", "DiagnosticData").Msg("timeout...")
			dChan <- lsp2.DiagnosticResult{Err: err}
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

//todo : move lsp presetantion concerns up
func sendHoversViaChan(hovers map[lsp.DocumentURI][]lsp2.HoverDetails, hoverChan chan lsp2.Hover) {
	for uri, hover := range hovers {
		hoverChan <- lsp2.Hover{
			Uri:   uri,
			Hover: hover,
		}
	}
}
