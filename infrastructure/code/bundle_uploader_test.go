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
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_Bundler_Upload(t *testing.T) {
	temporaryDir := setup(t)
	t.Cleanup(func() {
		_ = os.RemoveAll(temporaryDir)
	})

	c := config.CurrentConfig()
	t.Run("adds files to bundle", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeClient{C: c}
		var bundleUploader = BundleUploader{SnykCode: snykCodeService, instrumentor: NewCodeInstrumentor(), c: c}
		documentURI, bundleFile := createTempFileInDir(t, "bundleDoc.java", 10, temporaryDir)
		bundleFileMap := map[string]BundleFile{}
		bundleFileMap[documentURI] = bundleFile

		testTracker := progress.NewTestTracker(make(chan types.ProgressParams, 100000), make(chan bool, 1))
		_, err := bundleUploader.Upload(context.Background(), Bundle{SnykCode: snykCodeService, missingFiles: []string{documentURI}, logger: c.Logger()}, bundleFileMap, testTracker)

		assert.Equal(t, 1, snykCodeService.TotalBundleCount)
		assert.NoError(t, err)
	})

	t.Run("when loads of files breaks down in 4MB bundles", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeClient{C: c}
		var bundler = BundleUploader{SnykCode: snykCodeService, instrumentor: NewCodeInstrumentor(), c: c}

		bundleFileMap := map[string]BundleFile{}
		var missingFiles []string
		path, bundleFile := createTempFileInDir(t, "bundleDoc1.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir(t, "bundleDoc2.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir(t, "bundleDoc3.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir(t, "bundleDoc4.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir(t, "bundleDoc5.java", 100, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)

		testTracker := progress.NewTestTracker(make(chan types.ProgressParams, 100000), make(chan bool, 1))
		_, err := bundler.Upload(context.Background(), Bundle{SnykCode: snykCodeService, missingFiles: missingFiles, logger: c.Logger()}, bundleFileMap, testTracker)

		assert.True(t, snykCodeService.HasExtendedBundle)
		assert.Equal(t, 2, snykCodeService.TotalBundleCount)
		assert.Equal(t, 2, snykCodeService.ExtendedBundleCount)
		assert.Nil(t, err)
	})
}

func createTempFileInDir(t *testing.T, name string, size int, temporaryDir string) (string, BundleFile) {
	t.Helper()
	documentURI, fileContent := createFileOfSize(t, name, size, temporaryDir)
	return documentURI, BundleFile{Hash: util.Hash(fileContent), Content: string(fileContent)}
}

func Test_IsSupportedLanguage(t *testing.T) {
	c := testutil.UnitTest(t)
	const unsupportedFile = "C:\\some\\path\\Test.rs"
	snykCodeMock := &FakeSnykCodeClient{C: c}
	bundler := NewBundler(c, snykCodeMock, NewCodeInstrumentor())

	t.Run("should return true for supported languages", func(t *testing.T) {
		path := "C:\\some\\path\\Test.java"
		supported, _ := bundler.isSupported(context.Background(), path)
		assert.True(t, supported)
	})

	t.Run("should return false for unsupported languages", func(t *testing.T) {
		path := unsupportedFile
		supported, _ := bundler.isSupported(context.Background(), path)
		assert.False(t, supported)
	})

	t.Run("should cache supported extensions", func(t *testing.T) {
		path := unsupportedFile
		_, _ = bundler.isSupported(context.Background(), path)
		_, _ = bundler.isSupported(context.Background(), path)
		assert.Len(t, snykCodeMock.Calls, 1)
	})
}

func Test_IsSupported_ConfigFile(t *testing.T) {
	c := testutil.UnitTest(t)
	configFilesFromFiltersEndpoint := []string{
		".supportedConfigFile",
		".snyk",
		".dcignore",
		".gitignore",
	}
	expectedConfigFiles := []string{ // .dcignore and .gitignore should be excluded
		".supportedConfigFile",
		".snyk",
	}
	snykCodeMock := &FakeSnykCodeClient{
		ConfigFiles: configFilesFromFiltersEndpoint,
	}
	bundler := NewBundler(c, snykCodeMock, NewCodeInstrumentor())
	dir, _ := os.Getwd()

	t.Run("should return true for supported config files", func(t *testing.T) {
		for _, file := range expectedConfigFiles {
			path := filepath.Join(dir, file)
			supported, _ := bundler.isSupported(context.Background(), path)
			assert.True(t, supported)
		}
	})
	t.Run("should exclude .gitignore and .dcignore", func(t *testing.T) {
		for _, file := range []string{".gitignore", ".dcignore"} {
			path := filepath.Join(dir, file)
			supported, _ := bundler.isSupported(context.Background(), path)
			assert.False(t, supported)
		}
	})
	t.Run("should return false for unsupported config files", func(t *testing.T) {
		path := "C:\\some\\path\\.unsupported"
		supported, _ := bundler.isSupported(context.Background(), path)
		assert.False(t, supported)
	})

	t.Run("should cache supported extensions", func(t *testing.T) {
		path := "C:\\some\\path\\Test.rs"
		_, _ = bundler.isSupported(context.Background(), path)
		_, _ = bundler.isSupported(context.Background(), path)
		assert.Len(t, snykCodeMock.Calls, 1)
	})
}

func setup(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(xdg.DataHome, "createFileOfSize")
	if err != nil {
		t.Fatal(err, "Couldn't create test directory")
	}
	return dir
}

func createFileOfSize(t *testing.T, filename string, contentSize int, dir string) (string, []byte) {
	t.Helper()
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
