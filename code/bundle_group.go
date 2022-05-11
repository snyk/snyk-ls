package code

import (
	"errors"
	"github.com/rs/zerolog/log"
	"github.com/snyk/snyk-ls/config/environment"
	lsp2 "github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/util"
	"github.com/sourcegraph/go-lsp"
	"sync"
	"time"
)

type BundleGroup struct {
	SnykCode   SnykCodeService
	BundleHash string
	Bundles    []*Bundle
}

func (b *BundleGroup) AddBundle(bundle *Bundle) error {
	if len(b.Bundles) == 0 {
		err := b.createBundle(bundle)
		if err != nil {
			return err
		}
	} else {
		err := b.extendBundle(bundle)
		if err != nil {
			return err
		}
	}
	b.Bundles = append(b.Bundles, bundle)
	return nil
}

func (b *BundleGroup) createBundle(bundle *Bundle) error {
	var err error
	if bundle.hasContent() {
		b.BundleHash, _, err = b.SnykCode.CreateBundle(bundle.documents)
		log.Trace().Str("bundleHash", b.BundleHash).Msg("created bundle on backend")
	}
	return err
}

func (b *BundleGroup) extendBundle(segment *Bundle) error {
	var removeFiles []lsp.DocumentURI
	var err error
	if segment.hasContent() {
		b.BundleHash, _, err = b.SnykCode.ExtendBundle(b.BundleHash, segment.documents, removeFiles)
		log.Trace().Str("bundleHash", b.BundleHash).Msg("extended bundle on backend")
	}

	return err
}

func (b *BundleGroup) FetchDiagnosticsData(
	rootPath string,
	wg *sync.WaitGroup,
	dChan chan lsp2.DiagnosticResult,
	hoverChan chan lsp2.Hover,
) {
	defer wg.Done()
	defer log.Debug().Str("method", "FetchDiagnosticsData").Msg("done.")

	log.Debug().Str("method", "FetchDiagnosticsData").Msg("started.")

	b.retrieveAnalysis(rootPath, dChan, hoverChan)
}

func (b *BundleGroup) retrieveAnalysis(
	rootPath string,
	dChan chan lsp2.DiagnosticResult,
	hoverChan chan lsp2.Hover,
) {
	if len(b.Bundles) == 0 {
		return
	}

	for {
		start := time.Now()
		diags, hovers, status, err := b.SnykCode.RunAnalysis(
			b.BundleHash,
			getShardKey(rootPath, environment.Token()),
			[]lsp.DocumentURI{},
			0)

		if err != nil {
			log.Error().Err(err).
				Str("method", "DiagnosticData").Msg("error retrieving diagnostics...")
			dChan <- lsp2.DiagnosticResult{Err: err}
			return
		}

		if status == "COMPLETE" {
			for u, d := range diags {
				log.Trace().Str("method", "retrieveAnalysis").Str("bundleHash", b.BundleHash).
					Str("uri1", string(u)).
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

		if time.Since(start) > environment.SnykCodeAnalysisTimeout() {
			err = errors.New("analysis call timed out")
			log.Error().Err(err).Str("method", "DiagnosticData").Msg("timeout...")
			dChan <- lsp2.DiagnosticResult{Err: err}
		}
		time.Sleep(1 * time.Second)
	}
}

func getShardKey(rootPath string, authToken string) string {
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
