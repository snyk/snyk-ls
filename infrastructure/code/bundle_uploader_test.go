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
	"os"
	"testing"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_Bundler_Upload(t *testing.T) {
	temporaryDir := setup(t)
	t.Cleanup(func() {
		_ = os.RemoveAll(temporaryDir)
	})

	t.Run("adds files to bundle", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeClient{}
		var bundleUploader = BundleUploader{SnykCode: snykCodeService, instrumentor: performance.NewTestInstrumentor()}
		documentURI, bundleFile := createTempFileInDir("bundleDoc.java", 10, temporaryDir, t)
		bundleFileMap := map[string]BundleFile{}
		bundleFileMap[documentURI] = bundleFile

		_, err := bundleUploader.Upload(context.Background(), Bundle{SnykCode: snykCodeService, missingFiles: []string{documentURI}}, bundleFileMap)

		assert.Equal(t, 1, snykCodeService.TotalBundleCount)
		assert.NoError(t, err)
	})

	t.Run("when loads of files breaks down in 4MB bundles", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeClient{}
		var bundler = BundleUploader{SnykCode: snykCodeService, instrumentor: performance.NewTestInstrumentor()}

		bundleFileMap := map[string]BundleFile{}
		var missingFiles []string
		path, bundleFile := createTempFileInDir("bundleDoc1.java", (1024*1024)-1, temporaryDir, t)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir("bundleDoc2.java", (1024*1024)-1, temporaryDir, t)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir("bundleDoc3.java", (1024*1024)-1, temporaryDir, t)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir("bundleDoc4.java", (1024*1024)-1, temporaryDir, t)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir("bundleDoc5.java", 100, temporaryDir, t)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)

		_, err := bundler.Upload(context.Background(), Bundle{SnykCode: snykCodeService, missingFiles: missingFiles}, bundleFileMap)

		assert.True(t, snykCodeService.HasExtendedBundle)
		assert.Equal(t, 2, snykCodeService.TotalBundleCount)
		assert.Equal(t, 2, snykCodeService.ExtendedBundleCount)
		assert.Nil(t, err)
	})
}

func createTempFileInDir(name string, size int, temporaryDir string, t *testing.T) (string, BundleFile) {
	documentURI, fileContent := createFileOfSize(name, size, temporaryDir, t)
	return documentURI, BundleFile{Hash: util.Hash(fileContent), Content: string(fileContent)}
}

func Test_IsSupportedLanguage(t *testing.T) {
	snykCodeMock := &FakeSnykCodeClient{}
	bundler := NewBundler(snykCodeMock, performance.NewTestInstrumentor())

	t.Run("should return true for supported languages", func(t *testing.T) {
		path := "C:\\some\\path\\Test.java"
		supported := bundler.isSupported(context.Background(), path)
		assert.True(t, supported)
	})

	t.Run("should return false for unsupported languages", func(t *testing.T) {
		path := "C:\\some\\path\\Test.rs"
		supported := bundler.isSupported(context.Background(), path)
		assert.False(t, supported)
	})

	t.Run("should cache supported extensions", func(t *testing.T) {
		path := "C:\\some\\path\\Test.rs"
		bundler.isSupported(context.Background(), path)
		bundler.isSupported(context.Background(), path)
		assert.Len(t, snykCodeMock.Calls, 1)
	})
}

func setup(t *testing.T) string {
	dir, err := os.MkdirTemp(xdg.DataHome, "createFileOfSize")
	if err != nil {
		t.Fatal(err, "Couldn't create test directory")
	}
	return dir
}

func createFileOfSize(filename string, contentSize int, dir string, t *testing.T) (string, []byte) {
	buf := new(bytes.Buffer)
	buf.Grow(contentSize)
	for i := 0; i < contentSize; i++ {
		buf.WriteByte('a')
	}

	filePath := dir + string(os.PathSeparator) + filename
	err := os.WriteFile(filePath, buf.Bytes(), 0660)
	if err != nil {
		t.Fatal(err, "Couldn't write test file")
	}
	return filePath, buf.Bytes()
}
