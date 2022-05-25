package code

import (
	"context"
	"math"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
)

type BundleUploader struct {
	SnykCode            SnykCodeClient
	supportedExtensions concurrency.AtomicMap
	instrumentor        performance.Instrumentor
}

func NewBundler(SnykCode SnykCodeClient, instrumentor performance.Instrumentor) *BundleUploader {
	return &BundleUploader{
		SnykCode:            SnykCode,
		instrumentor:        instrumentor,
		supportedExtensions: concurrency.AtomicMap{},
	}
}

// TODO remove all LSP dependencies (e.g. DocumentURI)
func (b *BundleUploader) Upload(ctx context.Context, files []sglsp.DocumentURI) (Bundle, error) {
	method := "code.Upload"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	uploadBatches := b.groupInBatches(s.Context(), files)
	if len(uploadBatches) == 0 {
		return Bundle{}, nil
	}
	uploadedFiles := 0
	bundle := Bundle{
		SnykCode:     b.SnykCode,
		instrumentor: b.instrumentor,
	}
	t := progress.NewTracker(false)
	t.Begin("Snyk Code", "Uploading batches...")
	defer t.End("Upload done.")
	for i, uploadBatch := range uploadBatches {
		err := bundle.Upload(s.Context(), uploadBatch)
		if err != nil {
			return Bundle{}, err
		}
		uploadedFiles += len(uploadBatch.documents)
		percentage := float64(i) / float64(len(uploadBatches)) * 100
		t.Report(int(math.RoundToEven(percentage)))
	}
	return bundle, nil
}

func (b *BundleUploader) groupInBatches(ctx context.Context, files []sglsp.DocumentURI) []*UploadBatch {
	t := progress.NewTracker(false)
	t.Begin("Snyk Code", "Creating batches...")
	defer t.End("Batches created.")

	method := "code.groupInBatches"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	var batches []*UploadBatch
	uploadBatch := NewUploadBatch()
	for i, documentURI := range files {
		if !b.isSupported(ctx, documentURI) {
			continue
		}

		fileContent, err := loadContent(documentURI)
		if err != nil {
			log.Error().Err(err).Str("path1", string(documentURI)).Msg("could not load content of file")
			continue
		}

		if !(len(fileContent) > 0 && len(fileContent) <= maxFileSize) {
			continue
		}

		file := getFileFrom(fileContent)

		if len(batches) == 0 { // first batch added after first file found
			batches = append(batches, &uploadBatch)
		}

		if uploadBatch.canFitFile(string(documentURI), fileContent) {
			log.Trace().Str("path", string(documentURI)).Int("size", len(fileContent)).Msgf("added to bundle #%v", len(batches))
			uploadBatch.documents[documentURI] = file
		} else {
			log.Trace().Str("path", string(documentURI)).Int("size", len(fileContent)).Msgf("created new bundle - %v bundles in this upload so far", len(batches))
			newUploadBatch := NewUploadBatch()
			newUploadBatch.documents[documentURI] = file
			batches = append(batches, &newUploadBatch)
			uploadBatch = newUploadBatch
		}
		percentage := float64(i) / float64(len(files)) * 100
		t.Report(int(math.RoundToEven(percentage)))
	}
	return batches
}

func (b *BundleUploader) isSupported(ctx context.Context, documentURI sglsp.DocumentURI) bool {
	if b.supportedExtensions.Length() == 0 {
		// query
		_, exts, err := b.SnykCode.GetFilters(ctx)
		if err != nil {
			log.Error().Err(err).Msg("could not get filters")
			return false
		}

		// cache
		for _, ext := range exts {
			b.supportedExtensions.Put(ext, true)
		}
	}

	supported := b.supportedExtensions.Get(filepath.Ext(uri.PathFromUri(documentURI)))

	return supported != nil && supported.(bool)
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
