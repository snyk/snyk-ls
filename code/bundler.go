package code

import (
	"github.com/rs/zerolog/log"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/sourcegraph/go-lsp"
)

type Bundler struct {
	SnykCode SnykCodeService
}

// toDocumentURIMap Copies the atomic map over to a typed map
func toDocumentURIMap(input *concurrency.AtomicMap) map[lsp.DocumentURI]bool {
	output := map[lsp.DocumentURI]bool{}
	f := func(key interface{}, value interface{}) bool {
		output[key.(lsp.DocumentURI)] = value.(bool)
		return true
	}
	input.Range(f)
	return output
}

func (b *Bundler) createOrExtendBundles(documents map[lsp.DocumentURI]bool, bundles *[]*BundleImpl) {
	// we need a pointer to the array of bundle pointers to be able to grow it
	log.Debug().Str("method", "createOrExtendBundles").Msg("started")
	defer log.Debug().Str("method", "createOrExtendBundles").Msg("done")
	var bundle *BundleImpl
	toAdd := documents
	bundleIndex := len(*bundles) - 1
	var bundleFull bool
	for len(toAdd) > 0 {
		if bundleIndex == -1 || bundleFull {
			bundle = b.createBundle(bundles)
			log.Debug().Int("bundleCount", len(*bundles)).Msg("created new bundle")
		} else {
			bundle = (*bundles)[bundleIndex]
			log.Debug().Int("bundleCount", len(*bundles)).Msg("re-using bundle ")
		}
		toAdd = bundle.AddToBundleDocuments(toAdd).Files
		if len(toAdd) > 0 {
			log.Debug().Int("bundleCount", len(*bundles)).Msgf("File count: %d", len(bundle.BundleDocuments))
			bundleFull = true
		}
	}
}

func (b *Bundler) createBundle(bundles *[]*BundleImpl) *BundleImpl {
	bundle := BundleImpl{SnykCode: b.SnykCode}
	*bundles = append(*bundles, &bundle)
	return &bundle
}
