package iac

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config/environment"
	lsp2 "github.com/snyk/snyk-ls/lsp"
)

func Test_ScanWorkspace(t *testing.T) {
	environment.Load()
	environment.Format = environment.FormatHtml

	path, _ := filepath.Abs("testdata")
	doc := lsp.DocumentURI("file:" + path)

	dChan := make(chan lsp2.DiagnosticResult, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go ScanWorkspace(doc, &wg, dChan)
	wg.Wait()

	diagnosticResult := <-dChan
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))

	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_ScanFile(t *testing.T) {
	environment.Load()
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

	wg := sync.WaitGroup{}
	wg.Add(1)
	go ScanFile(doc.URI, &wg, dChan)
	wg.Wait()

	diagnosticResult := <-dChan
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))

	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_IacDiagnosticsRetrieval(t *testing.T) {
	path, _ := filepath.Abs("testdata/RBAC.yaml")

	cmd := exec.Command(environment.CliPath(), "iac", "test", path, "--json")
	res, err := scan(cmd)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanFile").Msg("Error while calling Snyk CLI")
	}

	var scanResults iacScanResult
	if err := json.Unmarshal(res, &scanResults); err != nil {
		log.Err(err).Str("method", "iac.ScanFile").Msg("Error while calling Snyk CLI")
	}

	diagnostics := convertDiagnostics(scanResults)
	assert.NotEqual(t, 0, len(diagnostics))
}
