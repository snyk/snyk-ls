package code

import (
	"github.com/rs/zerolog/log"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/util"
	sglsp "github.com/sourcegraph/go-lsp"
	"os"
)

type Bundler struct {
	SnykCode SnykCodeService
}

// TODO remove all LSP dependencies (e.g. DocumentURI)
func (b *Bundler) UploadFiles(files []sglsp.DocumentURI, onPartialUpload func(status UploadStatus)) (BundleGroup, error) {
	bundles := groupInBundles(files)
	uploadedFiles := 0
	bundleGroup := BundleGroup{
		SnykCode: b.SnykCode,
	}
	for _, bundle := range bundles {
		err := bundleGroup.AddBundle(bundle)
		if err != nil {
			return BundleGroup{}, err
		}
		uploadedFiles += len(bundle.documents)
		onPartialUpload(UploadStatus{
			UploadedFiles: uploadedFiles,
			TotalFiles:    len(files),
		})
	}
	return bundleGroup, nil
}

func groupInBundles(files []sglsp.DocumentURI) []*Bundle {
	currentSegment := NewBundle()
	segments := []*Bundle{&currentSegment}
	for _, documentURI := range files {
		if !IsSupported(documentURI) {
			continue
		}

		fileContent, err := loadContent(documentURI)
		if err != nil {
			log.Error().Err(err).Str("uri1", string(documentURI)).Msg("could not load content of file")
			continue
		}

		if !(len(fileContent) > 0 && len(fileContent) <= maxFileSize) {
			continue
		}

		file := getFileFrom(fileContent)
		if currentSegment.canFitFile(string(documentURI), fileContent) {
			log.Trace().Str("uri1", string(documentURI)).Int("size", len(fileContent)).Msgf("added to bundle #%v", len(segments))
			currentSegment.documents[documentURI] = file
			continue
		} else {
			log.Trace().Str("uri1", string(documentURI)).Int("size", len(fileContent)).Msgf("created new bundle - %v bundles in this upload so far", len(segments))
			currentSegment = NewBundle()
			currentSegment.documents[documentURI] = file
			segments = append(segments, &currentSegment)
			continue
		}
	}

	return segments
}

func loadContent(documentURI sglsp.DocumentURI) ([]byte, error) {
	path := uri.PathFromUri(documentURI)
	fileContent, err := os.ReadFile(path)
	return fileContent, err
}

func getFileFrom(content []byte) BundleFile {
	return BundleFile{
		Hash:    util.Hash(content),
		Content: string(content),
	}
}

func (b *Bundle) canFitFile(uri string, content []byte) bool {
	docPayloadSize := getTotalDocPayloadSize(uri, content)
	newSize := docPayloadSize + b.getSize()
	b.size += docPayloadSize
	return newSize < maxBundleSize
}

// toDocumentsURI Copies the atomic map over to a typed map
func toDocumentsURI(input *concurrency.AtomicMap) []sglsp.DocumentURI {
	var output []sglsp.DocumentURI
	f := func(key interface{}, value interface{}) bool {
		output = append(output, key.(sglsp.DocumentURI))
		return true
	}
	input.Range(f)
	return output
}
