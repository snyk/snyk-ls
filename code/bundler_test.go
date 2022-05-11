package code

import (
	"bytes"
	"github.com/rs/zerolog/log"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_Bundler_Upload(t *testing.T) {
	temporaryDir := setup()
	t.Run("adds files to bundle", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeApiService{}
		var bundler = Bundler{SnykCode: snykCodeService}
		files := []lsp.DocumentURI{createFileOfSize("bundleDoc.java", 10, temporaryDir)}

		_, err := bundler.UploadFiles(files, noop)

		assert.True(t, snykCodeService.HasCreatedNewBundle)
		assert.Equal(t, snykCodeService.TotalBundleCount, 1)
		assert.Nil(t, err)
	})

	t.Run("when loads of files breaks down in 4MB bundles", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeApiService{}
		var bundler = Bundler{SnykCode: snykCodeService}
		files := []lsp.DocumentURI{
			createFileOfSize("bundleDoc1.java", (1024*1024)-1, temporaryDir),
			createFileOfSize("bundleDoc2.java", (1024*1024)-1, temporaryDir),
			createFileOfSize("bundleDoc3.java", (1024*1024)-1, temporaryDir),
			createFileOfSize("bundleDoc4.java", (1024*1024)-1, temporaryDir),
			createFileOfSize("bundleDoc5.java", 100, temporaryDir),
		}

		_, err := bundler.UploadFiles(files, noop)

		assert.True(t, snykCodeService.HasCreatedNewBundle)
		assert.True(t, snykCodeService.HasExtendedBundle)
		assert.Equal(t, snykCodeService.TotalBundleCount, 2)
		assert.Equal(t, snykCodeService.ExtendedBundleCount, 1)
		assert.Nil(t, err)
	})

	t.Run("when too big ignores file", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeApiService{}
		var bundler = Bundler{SnykCode: snykCodeService}
		files := []lsp.DocumentURI{createFileOfSize("bundleDoc.java", 1024*1024+1, temporaryDir)}

		_, err := bundler.UploadFiles(files, noop)

		assert.False(t, snykCodeService.HasCreatedNewBundle)
		assert.Nil(t, err)
	})

	t.Run("when empty file ignores file", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeApiService{}
		var bundler = Bundler{SnykCode: snykCodeService}
		files := []lsp.DocumentURI{createFileOfSize("bundleDoc.java", 0, temporaryDir)}

		_, err := bundler.UploadFiles(files, noop)

		assert.False(t, snykCodeService.HasCreatedNewBundle)
		assert.Nil(t, err)
	})

	t.Run("when unsupported ignores file", func(t *testing.T) {
		snykCodeService := &FakeSnykCodeApiService{}
		var bundler = Bundler{SnykCode: snykCodeService}
		files := []lsp.DocumentURI{createFileOfSize("bundleDoc.mr_robot", 1, temporaryDir)}

		_, err := bundler.UploadFiles(files, noop)

		assert.False(t, snykCodeService.HasCreatedNewBundle)
		assert.Nil(t, err)
	})

	t.Cleanup(func() {
		defer os.RemoveAll(temporaryDir)
	})
}

func setup() string {
	dir, err := os.MkdirTemp(os.TempDir(), "createFileOfSize")
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create test directory")
	}
	return dir
}

func createFileOfSize(filename string, contentSize int, dir string) lsp.DocumentURI {
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
	return bundleDoc.URI
}

func noop(status UploadStatus) {}
