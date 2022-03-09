package iac

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	lsp2 "github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/util"
)

func Test_HandleFile(t *testing.T) {
	util.Load()
	util.Format = util.FormatHtml
	path, _ := filepath.Abs("testdata/RBAC.yaml")
	content, _ := os.ReadFile(path)
	doc := lsp.TextDocumentItem{
		URI:        lsp.DocumentURI(path),
		LanguageID: "json",
		Version:    0,
		Text:       string(content),
	}
	dChan := make(chan lsp2.DiagnosticResult, 1)
	clChan := make(chan lsp2.CodeLensResult, 1)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go HandleFile(doc.URI, &wg, dChan, clChan)
	diagnosticResult := <-dChan
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	codeLensResult := <-clChan
	assert.NotEqual(t, 0, len(codeLensResult.CodeLenses))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_fetch_shouldProvideDiagnostics(t *testing.T) {
	path, _ := filepath.Abs("testdata/RBAC.yaml")
	diagnostics, _, _ := fetch(path)
	assert.NotEqual(t, 0, len(diagnostics))
}

func Test_fetch_shouldProvideCodeLenses(t *testing.T) {
	path, _ := filepath.Abs("testdata/RBAC.yaml")
	_, codeLenses, _ := fetch(path)
	assert.NotEqual(t, 0, len(codeLenses))
}

func Test_convertCodeLenses_shouldOneCodeLensPerIssue(t *testing.T) {
	bytes, _ := os.ReadFile("testdata/RBAC-iac-result.json")

	var iacResult testResult
	_ = json.Unmarshal(bytes, &iacResult)
	assert.NotNil(t, iacResult)
	assert.True(t, len(iacResult.IacIssues) > 0)

	actual := convertCodeLenses(iacResult)

	assert.Equal(t, len(iacResult.IacIssues), len(actual))
}
