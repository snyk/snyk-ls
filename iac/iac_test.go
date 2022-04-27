package iac

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/testutil"
	lsp2 "github.com/snyk/snyk-ls/lsp"
)

func Test_ScanWorkspace(t *testing.T) {
	testutil.IntegTest(t)
	environment.Load()
	environment.EnsureCLI()
	environment.Format = environment.FormatHtml

	path, _ := filepath.Abs("testdata")
	doc := lsp.DocumentURI("file:" + path)

	dChan := make(chan lsp2.DiagnosticResult, 1)
	clChan := make(chan lsp2.CodeLensResult, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := cli.SnykCli{}
	go ScanWorkspace(snykCli, doc, &wg, dChan, clChan)
	wg.Wait()

	diagnosticResult := <-dChan
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))

	codeLensResult := <-clChan
	assert.NotEqual(t, 0, len(codeLensResult.CodeLenses))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_ScanFile(t *testing.T) {
	testutil.IntegTest(t)
	environment.Load()
	environment.EnsureCLI()
	environment.Format = environment.FormatHtml

	path, _ := filepath.Abs("testdata/RBAC.yaml")
	content, _ := os.ReadFile(path)

	doc := lsp.TextDocumentItem{
		URI:        lsp.DocumentURI(path),
		LanguageID: "yaml",
		Version:    0,
		Text:       string(content),
	}

	dChan := make(chan lsp2.DiagnosticResult, 1)
	clChan := make(chan lsp2.CodeLensResult, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := cli.SnykCli{}
	go ScanFile(snykCli, doc.URI, &wg, dChan, clChan)
	wg.Wait()

	diagnosticResult := <-dChan
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))

	codeLensResult := <-clChan
	assert.NotEqual(t, 0, len(codeLensResult.CodeLenses))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}
