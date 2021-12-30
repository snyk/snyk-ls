package oss

import (
	lsp2 "github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/util"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func Test_HandleFile(t *testing.T) {
	util.Load()
	util.Format = util.FormatHtml
	path, _ := filepath.Abs("testdata/package.json")
	content, _ := os.ReadFile(path)
	doc := lsp.TextDocumentItem{
		URI:        lsp.DocumentURI(path),
		LanguageID: "json",
		Version:    0,
		Text:       string(content),
	}
	dChan := make(chan lsp2.DiagnosticResult)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go HandleFile(doc, &wg, dChan, nil)
	diagnosticResult := <-dChan
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}
