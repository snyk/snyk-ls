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
	"math"
	"os"
	"path/filepath"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/util"
)

type BundleUploader struct {
	SnykCode             SnykCodeClient
	supportedExtensions  *xsync.MapOf[string, bool]
	supportedConfigFiles *xsync.MapOf[string, bool]
	instrumentor         performance.Instrumentor
}

func NewBundler(SnykCode SnykCodeClient, instrumentor performance.Instrumentor) *BundleUploader {
	return &BundleUploader{
		SnykCode:             SnykCode,
		instrumentor:         instrumentor,
		supportedExtensions:  xsync.NewMapOf[bool](),
		supportedConfigFiles: xsync.NewMapOf[bool](),
	}
}

func (b *BundleUploader) Upload(ctx context.Context, bundle Bundle, files map[string]BundleFile) (Bundle, error) {
	method := "code.Upload"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	uploadBatches := b.groupInBatches(s.Context(), bundle, files)
	if len(uploadBatches) == 0 {
		return bundle, nil
	}

	uploadedFiles := 0
	t := progress.NewTracker(false)
	t.Begin("Snyk Code analysis for "+bundle.rootPath, "Uploading batches...")
	defer t.End("Upload done.")
	for i, uploadBatch := range uploadBatches {
		if err := ctx.Err(); err != nil {
			return bundle, err
		}
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

func (b *BundleUploader) groupInBatches(
	ctx context.Context,
	bundle Bundle,
	files map[string]BundleFile,
) []*UploadBatch {
	t := progress.NewTracker(false)
	t.Begin("Snyk Code analysis for "+bundle.rootPath, "Creating batches...")
	defer t.End("Batches created.")

	method := "code.groupInBatches"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	var batches []*UploadBatch
	uploadBatch := NewUploadBatch()
	var i = 0
	for _, documentURI := range bundle.missingFiles {
		if len(batches) == 0 { // first batch added after first file found
			batches = append(batches, &uploadBatch)
		}

		file := files[documentURI]
		var fileContent = []byte(file.Content)
		if uploadBatch.canFitFile(documentURI, fileContent) {
			log.Trace().Str("path", documentURI).Int("size", len(fileContent)).Msgf("added to bundle #%v", len(batches))
			uploadBatch.documents[documentURI] = file
		} else {
			log.Trace().Str("path", documentURI).Int("size",
				len(fileContent)).Msgf("created new bundle - %v bundles in this upload so far", len(batches))
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

func (b *BundleUploader) isSupported(ctx context.Context, file string) bool {
	if b.supportedExtensions.Size() == 0 && b.supportedConfigFiles.Size() == 0 {
		configFiles, extensions, err := b.SnykCode.GetFilters(ctx)
		if err != nil {
			log.Error().Err(err).Msg("could not get filters")
			return false
		}

		for _, ext := range extensions {
			b.supportedExtensions.Store(ext, true)
		}
		for _, configFile := range configFiles {
			b.supportedConfigFiles.Store(configFile, true)
		}
	}

	fileExtension := filepath.Ext(file)
	fileName := filepath.Base(file) // Config files are compared to the file name, not just the extensions
	_, isSupportedExtension := b.supportedExtensions.Load(fileExtension)
	_, isSupportedConfigFile := b.supportedConfigFiles.Load(fileName)

	return isSupportedExtension || isSupportedConfigFile
}

func loadContent(filePath string) ([]byte, error) {
	fileContent, err := os.ReadFile(filePath)
	return fileContent, err
}

func getFileFrom(filePath string, content []byte) BundleFile {
	file := BundleFile{
		Hash:    util.Hash(content),
		Content: string(content),
	}
	log.Trace().Str("method", "getFileFrom").Str("hash", file.Hash).Str("filePath", filePath).Send()
	return file
}
