package oss

import (
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func Test_callSnykCLI(t *testing.T) {
	path, _ := filepath.Abs("testdata/package.json")
	content, _ := os.ReadFile(path)
	diagnostics, _ := callSnykCLI(lsp.TextDocumentItem{
		URI:        lsp.DocumentURI(path),
		LanguageID: "json",
		Version:    0,
		Text:       string(content),
	})
	assert.NotEqual(t, 0, len(diagnostics))
}
