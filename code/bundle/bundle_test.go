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
	bundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	assert.NotEqual(t, "", createBundleFromSource(registeredDocuments))
	assert.NotEqual(t, "", bundleHash)
}

func Test_createBundleFromSource_shouldAddDocumentToBundle(t *testing.T) {
	bundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	bundleHash := createBundleFromSource(registeredDocuments)

	assert.NotEqual(t, "", bundleHash)
	assert.NotEqual(t, File{}, bundleDocuments[firstDoc.URI])
	assert.Equal(t, firstBundleFile, bundleDocuments[firstDoc.URI])
}

func Test_extendBundleFromSource_shouldAddDocumentToBundle(t *testing.T) {
	bundleHash = "test-hash"
	bundleDocuments = map[lsp.DocumentURI]File{}
	bundleDocuments[firstDoc.URI] = firstBundleFile
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[secondDoc.URI] = secondDoc

	secondBundleFile := File{
		hash:    hash(secondDoc.Text),
		content: secondDoc.Text,
	}

	missingFiles := extendBundleFromSource(registeredDocuments)
	assert.Empty(t, missingFiles)
	assert.Equal(t, secondBundleFile, bundleDocuments[secondDoc.URI])
}
