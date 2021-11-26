package bundle

import (
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	firstDoc = lsp.TextDocumentItem{
		URI:        "/test1.java",
		LanguageID: "java",
		Version:    0,
		Text:       "class1",
	}

	secondDoc = lsp.TextDocumentItem{
		URI:        "/test2.java",
		LanguageID: "java",
		Version:    3,
		Text:       "class2",
	}

	firstBundleFile = File{
		hash:    hash(firstDoc.Text),
		content: firstDoc.Text,
	}
)

func Test_hash(t *testing.T) {
	assert.Equal(t,
		"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		hash("hello\n"),
	)
}

func Test_createBundleFromSource_shouldReturnNonEmptyBundleHash(t *testing.T) {
	b := CodeBundleImpl{Backend: &FakeBackendService{BundleHash: "test-bundle-hash"}}
	b.bundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	assert.NotEqual(t, "", b.createBundleFromSource(registeredDocuments))
	assert.NotEqual(t, "", b.bundleHash)
}

func Test_createBundleFromSource_shouldAddDocumentToBundle(t *testing.T) {
	b := CodeBundleImpl{Backend: &FakeBackendService{BundleHash: "test-bundle-hash"}}
	b.bundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	bundleHash := b.createBundleFromSource(registeredDocuments)

	assert.NotEqual(t, "", bundleHash)
	assert.NotEqual(t, File{}, b.bundleDocuments[firstDoc.URI])
	assert.Equal(t, firstBundleFile, b.bundleDocuments[firstDoc.URI])
}

func Test_extendBundleFromSource_shouldAddDocumentToBundle(t *testing.T) {
	b := CodeBundleImpl{Backend: &FakeBackendService{BundleHash: "test-bundle-hash"}}
	b.bundleHash = "test-hash"
	b.bundleDocuments = map[lsp.DocumentURI]File{}
	b.bundleDocuments[firstDoc.URI] = firstBundleFile
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[secondDoc.URI] = secondDoc

	secondBundleFile := File{
		hash:    hash(secondDoc.Text),
		content: secondDoc.Text,
	}

	missingFiles := b.extendBundleFromSource(registeredDocuments, []lsp.DocumentURI{})
	assert.Empty(t, missingFiles)
	assert.Equal(t, secondBundleFile, b.bundleDocuments[secondDoc.URI])
}
