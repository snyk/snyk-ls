package code

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/util"
)

type BundleUploader struct {
	SnykCode            SnykCodeClient
	supportedExtensions concurrency.AtomicMap
}

func NewBundler(SnykCode SnykCodeClient) *BundleUploader {
	return &BundleUploader{
		SnykCode:            SnykCode,
		supportedExtensions: concurrency.AtomicMap{},
	}
}

// TODO remove all LSP dependencies (e.g. DocumentURI)
func (b *BundleUploader) Upload(files []sglsp.DocumentURI, onPartialUpload func(status UploadStatus)) (Bundle, error) {
	uploadBatches := b.groupInBatches(files)
	uploadedFiles := 0
	bundle := Bundle{
		SnykCode: b.SnykCode,
	}
	for _, uploadBatch := range uploadBatches {
		err := bundle.Upload(uploadBatch)
		if err != nil {
			return Bundle{}, err
		}
		uploadedFiles += len(uploadBatch.documents)
		onPartialUpload(UploadStatus{
			UploadedFiles: uploadedFiles,
			TotalFiles:    len(files),
		})
	}
	return bundle, nil
}

func (b *BundleUploader) groupInBatches(files []sglsp.DocumentURI) []*UploadBatch {
	uploadBatch := NewUploadBatch()
	batches := []*UploadBatch{&uploadBatch}
	for _, documentURI := range files {
		if !b.isSupported(documentURI) {
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
		if uploadBatch.canFitFile(string(documentURI), fileContent) {
			log.Trace().Str("uri1", string(documentURI)).Int("size", len(fileContent)).Msgf("added to bundle #%v", len(batches))
			uploadBatch.documents[documentURI] = file
			continue
		} else {
			log.Trace().Str("uri1", string(documentURI)).Int("size", len(fileContent)).Msgf("created new bundle - %v bundles in this upload so far", len(batches))
			newUploadBatch := NewUploadBatch()
			newUploadBatch.documents[documentURI] = file
			batches = append(batches, &newUploadBatch)
			uploadBatch = newUploadBatch
			continue
		}
	}

	return batches
}

func (b *BundleUploader) isSupported(documentURI sglsp.DocumentURI) bool {
	if b.supportedExtensions.Length() == 0 {
		// query
		_, exts, err := b.SnykCode.GetFilters()
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
