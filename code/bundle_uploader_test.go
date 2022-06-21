package code

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_Bundler_Upload(t *testing.T) {
	temporaryDir := setup()
	t.Run("adds files to bundle", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeClient{}
		var bundleUploader = BundleUploader{SnykCode: snykCodeService, instrumentor: &performance.TestInstrumentor{}}
		documentURI, bundleFile := createTempFileInDir("bundleDoc.java", 10, temporaryDir)
		bundleFileMap := map[lsp.DocumentURI]BundleFile{}
		bundleFileMap[documentURI] = bundleFile

		_, err := bundleUploader.Upload(context.Background(), Bundle{SnykCode: snykCodeService, missingFiles: []lsp.DocumentURI{documentURI}}, bundleFileMap)

		assert.Equal(t, 1, snykCodeService.TotalBundleCount)
		assert.NoError(t, err)
	})

	t.Run("when loads of files breaks down in 4MB bundles", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeClient{}
		var bundler = BundleUploader{SnykCode: snykCodeService, instrumentor: &performance.TestInstrumentor{}}

		bundleFileMap := map[lsp.DocumentURI]BundleFile{}
		var missingFiles []lsp.DocumentURI
		documentURI, bundleFile := createTempFileInDir("bundleDoc1.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[documentURI] = bundleFile
		missingFiles = append(missingFiles, documentURI)
		documentURI, bundleFile = createTempFileInDir("bundleDoc2.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[documentURI] = bundleFile
		missingFiles = append(missingFiles, documentURI)
		documentURI, bundleFile = createTempFileInDir("bundleDoc3.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[documentURI] = bundleFile
		missingFiles = append(missingFiles, documentURI)
		documentURI, bundleFile = createTempFileInDir("bundleDoc4.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[documentURI] = bundleFile
		missingFiles = append(missingFiles, documentURI)
		documentURI, bundleFile = createTempFileInDir("bundleDoc5.java", 100, temporaryDir)
		bundleFileMap[documentURI] = bundleFile
		missingFiles = append(missingFiles, documentURI)

		_, err := bundler.Upload(context.Background(), Bundle{SnykCode: snykCodeService, missingFiles: missingFiles}, bundleFileMap)

		assert.True(t, snykCodeService.HasExtendedBundle)
		assert.Equal(t, 2, snykCodeService.TotalBundleCount)
		assert.Equal(t, 2, snykCodeService.ExtendedBundleCount)
		assert.Nil(t, err)
	})

	t.Cleanup(func() {
		defer os.RemoveAll(temporaryDir)
	})
}

func createTempFileInDir(name string, size int, temporaryDir string) (lsp.DocumentURI, BundleFile) {
	documentURI, fileContent := createFileOfSize(name, size, temporaryDir)
	return documentURI, BundleFile{Hash: util.Hash(fileContent), Content: string(fileContent)}
}

func Test_IsSupportedLanguage(t *testing.T) {
	snykCodeMock := &FakeSnykCodeClient{}
	bundler := NewBundler(snykCodeMock, &performance.TestInstrumentor{})

	t.Run("should return true for supported languages", func(t *testing.T) {
		documentURI := uri.PathToUri("C:\\some\\path\\Test.java")
		supported := bundler.isSupported(context.Background(), documentURI)
		assert.True(t, supported)
	})

	t.Run("should return false for unsupported languages", func(t *testing.T) {
		documentURI := uri.PathToUri("C:\\some\\path\\Test.rs")
		supported := bundler.isSupported(context.Background(), documentURI)
		assert.False(t, supported)
	})

	t.Run("should cache supported extensions", func(t *testing.T) {
		documentURI := uri.PathToUri("C:\\some\\path\\Test.rs")
		bundler.isSupported(context.Background(), documentURI)
		bundler.isSupported(context.Background(), documentURI)
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

func createFileOfSize(filename string, contentSize int, dir string) (lsp.DocumentURI, []byte) {
	buf := new(bytes.Buffer)
	buf.Grow(contentSize)
	for i := 0; i < contentSize; i++ {
		buf.WriteByte('a')
	}

	filePath := dir + string(os.PathSeparator) + filename
	bundleDoc := lsp.TextDocumentItem{URI: uri.PathToUri(filePath)}
	err := os.WriteFile(filePath, buf.Bytes(), 0660)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't write test file")
	}
	return bundleDoc.URI, buf.Bytes()
}
