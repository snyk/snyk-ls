package iac

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
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
	hoverChan := make(chan lsp2.Hover, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := cli.SnykCli{}
	go ScanWorkspace(snykCli, doc, &wg, dChan, hoverChan)
	wg.Wait()

	diagnosticResult := <-dChan
	hoverResult := <-hoverChan

	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	assert.NotEqual(t, 0, len(hoverResult.Hover))

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
	hoverChan := make(chan lsp2.Hover, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := cli.SnykCli{}
	go ScanFile(snykCli, doc.URI, &wg, dChan, hoverChan)
	wg.Wait()

	diagnosticResult := <-dChan
	hoverResult := <-hoverChan

	assert.NotEqual(t, 0, len(hoverResult.Hover))
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))

	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_IacDiagnosticsRetrieval(t *testing.T) {
	testutil.IntegTest(t)
	path, _ := filepath.Abs("testdata/RBAC.yaml")

	cmd := cliCmd(uri.PathToUri(path))
	var snykCli = cli.SnykCli{}
	res, err := snykCli.Execute(cmd)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanFile").Msg("Error while calling Snyk CLI")
	}

	var scanResults iacScanResult
	if err := json.Unmarshal(res, &scanResults); err != nil {
		log.Err(err).Str("method", "iac.ScanFile").Msg("Error while calling Snyk CLI")
	}

	diagnostics, hovers := convertDiagnostics(scanResults)
	assert.NotEqual(t, 0, len(diagnostics))
	assert.NotEqual(t, 0, len(hovers))
}
