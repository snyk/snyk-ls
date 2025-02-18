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
	"bytes"
	"context"
	"math"
	"os"
	"path/filepath"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"

	codeClientObservability "github.com/snyk/code-client-go/observability"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

type BundleUploader struct {
	SnykCode             SnykCodeClient
	supportedExtensions  *xsync.MapOf[string, bool]
	supportedConfigFiles *xsync.MapOf[string, bool]
	instrumentor         codeClientObservability.Instrumentor
	c                    *config.Config
}

func NewBundler(c *config.Config, SnykCode SnykCodeClient, instrumentor codeClientObservability.Instrumentor) *BundleUploader {
	return &BundleUploader{
		SnykCode:             SnykCode,
		instrumentor:         instrumentor,
		supportedExtensions:  xsync.NewMapOf[bool](),
		supportedConfigFiles: xsync.NewMapOf[bool](),
		c:                    c,
	}
}

func (b *BundleUploader) Upload(ctx context.Context, bundle Bundle, t *progress.Tracker) (Bundle, error) {
	method := "code.Upload"
	logger := b.c.Logger().With().Str("method", method).Logger()
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	t.ReportWithMessage(16, "uploading batches...")
	defer t.ReportWithMessage(20, "upload done.")

	for len(bundle.missingFiles) > 0 {
		if s.Context().Err() != nil || t.IsCanceled() {
			progress.Cancel(t.GetToken())
			logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return Bundle{}, ctx.Err()
		}
		uploadBatches := b.groupInBatches(s.Context(), bundle, t)
		if len(uploadBatches) == 0 {
			return bundle, nil
		}

		uploadedFiles := 0
		for i, uploadBatch := range uploadBatches {
			if s.Context().Err() != nil || t.IsCanceled() {
				progress.Cancel(t.GetToken())
				logger.Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
				return Bundle{}, ctx.Err()
			}

			b.enrichBatchWithFileContent(uploadBatch, bundle.rootPath, logger)

			err := bundle.Upload(s.Context(), uploadBatch)
			if err != nil {
				return Bundle{}, err
			}
			uploadedFiles += len(uploadBatch.documents)
			// Clear out documents in uploaded batch
			uploadBatch.documents = make(map[types.FilePath]BundleFile)
			percentage := float64(i) / float64(len(uploadBatches)) * 100
			t.Report(int(math.RoundToEven(percentage)))
		}
	}
	// bundle doesn't need file map anymore since they are already grouped and uploaded
	bundle.Files = make(map[types.FilePath]BundleFile)

	return bundle, nil
}

func (b *BundleUploader) enrichBatchWithFileContent(uploadBatch *UploadBatch, workDir types.FilePath, logger zerolog.Logger) {
	for filePath, bundleFile := range uploadBatch.documents {
		absPath, err := DecodePath(ToAbsolutePath(workDir, filePath))
		if err != nil {
			logger.Error().Err(err).Str("file", string(filePath)).Msg("Failed to decode Path")
			continue
		}
		content, err := os.ReadFile(absPath)
		if err != nil {
			logger.Error().Err(err).Str("file", string(filePath)).Msg("Failed to read bundle file")
			continue
		}
		utf8Content, err := util.ConvertToUTF8(bytes.NewReader(content))
		if err != nil {
			logger.Error().Err(err).Str("file", string(filePath)).Msg("Failed to convert bundle file to UTF-8")
			continue
		}
		bundleFile.Content = string(utf8Content)
		uploadBatch.documents[filePath] = bundleFile
	}
}

func (b *BundleUploader) groupInBatches(ctx context.Context, bundle Bundle, t *progress.Tracker) []*UploadBatch {
	method := "code.groupInBatches"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)
	t.ReportWithMessage(21, "creating batches...")
	defer t.ReportWithMessage(30, "batches created and uploaded")

	var batches []*UploadBatch
	uploadBatch := NewUploadBatch()
	var i = 0
	for _, filePath := range bundle.missingFiles {
		if len(batches) == 0 { // first batch added after first file found
			batches = append(batches, uploadBatch)
		}

		file := bundle.Files[filePath]
		if uploadBatch.canFitFile(filePath, file.Size) {
			b.c.Logger().Trace().Str("path", string(filePath)).Int("size", file.Size).Msgf("added to bundle #%v", len(batches))
			uploadBatch.documents[filePath] = file
		} else {
			b.c.Logger().Trace().Str("path", string(filePath)).Int("size",
				file.Size).Msgf("created new bundle - %v bundles in this upload so far", len(batches))
			newUploadBatch := NewUploadBatch()
			newUploadBatch.documents[filePath] = file
			batches = append(batches, newUploadBatch)
			uploadBatch = newUploadBatch
		}
		percentage := float64(i) / float64(len(bundle.Files)) * 100
		t.Report(int(math.RoundToEven(percentage)))
	}
	return batches
}

func (b *BundleUploader) isSupported(ctx context.Context, file string) (bool, error) {
	if b.supportedExtensions.Size() == 0 && b.supportedConfigFiles.Size() == 0 {
		filters, err := b.SnykCode.GetFilters(ctx)
		if err != nil {
			b.c.Logger().Error().Err(err).Msg("could not get filters")
			return false, err
		}

		for _, ext := range filters.Extensions {
			b.supportedExtensions.Store(ext, true)
		}
		for _, configFile := range filters.ConfigFiles {
			// .gitignore and .dcignore should not be uploaded
			// (https://github.com/snyk/code-client/blob/d6f6a2ce4c14cb4b05aa03fb9f03533d8cf6ca4a/src/files.ts#L138)
			if configFile == ".gitignore" || configFile == ".dcignore" {
				continue
			}
			b.supportedConfigFiles.Store(configFile, true)
		}
	}

	fileExtension := filepath.Ext(file)
	fileName := filepath.Base(file) // Config files are compared to the file name, not just the extensions
	_, isSupportedExtension := b.supportedExtensions.Load(fileExtension)
	_, isSupportedConfigFile := b.supportedConfigFiles.Load(fileName)

	return isSupportedExtension || isSupportedConfigFile, nil
}

func (sc *Scanner) getFileFrom(filePath string, utf8FileContent []byte) BundleFile {
	file := BundleFile{
		Hash: util.HashWithoutConversion(utf8FileContent),
		Size: len(utf8FileContent),
	}
	sc.C.Logger().Trace().Str("method", "getFileFrom").Str("hash", file.Hash).Str("filePath", filePath).Send()
	return file
}
