package code

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_Bundler_Upload(t *testing.T) {
	temporaryDir := setup()
	t.Cleanup(func() {
		defer os.RemoveAll(temporaryDir)
	})

	t.Run("adds files to bundle", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeClient{}
		var bundleUploader = BundleUploader{SnykCode: snykCodeService, instrumentor: performance.NewTestInstrumentor()}
		documentURI, bundleFile := createTempFileInDir("bundleDoc.java", 10, temporaryDir)
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
		path, bundleFile := createTempFileInDir("bundleDoc1.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir("bundleDoc2.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir("bundleDoc3.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir("bundleDoc4.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir("bundleDoc5.java", 100, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)

		_, err := bundler.Upload(context.Background(), Bundle{SnykCode: snykCodeService, missingFiles: missingFiles}, bundleFileMap)

		assert.True(t, snykCodeService.HasExtendedBundle)
		assert.Equal(t, 2, snykCodeService.TotalBundleCount)
		assert.Equal(t, 2, snykCodeService.ExtendedBundleCount)
		assert.Nil(t, err)
	})
}

func createTempFileInDir(name string, size int, temporaryDir string) (string, BundleFile) {
	documentURI, fileContent := createFileOfSize(name, size, temporaryDir)
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

func setup() string {
	dir, err := os.MkdirTemp(os.TempDir(), "createFileOfSize")
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create test directory")
	}
	return dir
}

func createFileOfSize(filename string, contentSize int, dir string) (string, []byte) {
	buf := new(bytes.Buffer)
	buf.Grow(contentSize)
	for i := 0; i < contentSize; i++ {
		buf.WriteByte('a')
	}

	filePath := dir + string(os.PathSeparator) + filename
	err := os.WriteFile(filePath, buf.Bytes(), 0660)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't write test file")
	}
	return filePath, buf.Bytes()
}
