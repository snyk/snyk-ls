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
	if !environment.RunIntegTest {
		t.Skip("set " + environment.INTEG_TESTS + " to run integration tests")
	}
	environment.Load()
	environment.Format = environment.FormatHtml

	path, _ := filepath.Abs("testdata")
	doc := lsp.DocumentURI("file:" + path)

	dChan := make(chan lsp2.DiagnosticResult, 1)
	clChan := make(chan lsp2.CodeLensResult, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go ScanWorkspace(doc, &wg, dChan, clChan)
	wg.Wait()

	diagnosticResult := <-dChan
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))

	codeLensResult := <-clChan
	assert.NotEqual(t, 0, len(codeLensResult.CodeLenses))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_ScanFile(t *testing.T) {
	if !environment.RunIntegTest {
		t.Skip("set " + environment.INTEG_TESTS + " to run integration tests")
	}
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
	clChan := make(chan lsp2.CodeLensResult, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go ScanFile(doc.URI, &wg, dChan, clChan)
	wg.Wait()

	diagnosticResult := <-dChan
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))

	codeLensResult := <-clChan
	assert.NotEqual(t, 0, len(codeLensResult.CodeLenses))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_IacDiagnosticsRetrieval(t *testing.T) {
	if !environment.RunIntegTest {
		t.Skip("set " + environment.INTEG_TESTS + " to run integration tests")
	}
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

func Test_IacCodelensRetrieval(t *testing.T) {
	if !environment.RunIntegTest {
		t.Skip("set " + environment.INTEG_TESTS + " to run integration tests")
	}
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

	codeLenses := convertCodeLenses(scanResults)
	assert.NotEqual(t, 0, len(codeLenses))
}

func Test_convertCodeLenses_shouldOneCodeLensPerIssue(t *testing.T) {
	bytes, _ := os.ReadFile("testdata/RBAC-iac-result.json")

	var iacResult iacScanResult
	_ = json.Unmarshal(bytes, &iacResult)
	assert.NotNil(t, iacResult)
	assert.True(t, len(iacResult.IacIssues) > 0)

	actual := convertCodeLenses(iacResult)

	assert.Equal(t, len(iacResult.IacIssues), len(actual))
}
