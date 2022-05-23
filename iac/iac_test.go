package iac

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/hover"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/testutil"
	lsp2 "github.com/snyk/snyk-ls/lsp"
)

func Test_ScanWorkspace(t *testing.T) {
	testutil.IntegTest(t)
	testutil.CreateDummyProgressListener(t)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)
	config.CurrentConfig().SetFormat(config.FormatHtml)

	path, _ := filepath.Abs("testdata")
	doc := lsp.DocumentURI("file:" + path)

	dChan := make(chan lsp2.DiagnosticResult, 1)
	hoverChan := make(chan lsp2.Hover, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := cli.SnykCli{}
	go ScanWorkspace(ctx, snykCli, doc, &wg, dChan, hoverChan)
	wg.Wait()

	diagnosticResult := <-dChan
	hoverResult := <-hoverChan

	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	assert.NotEqual(t, 0, len(hoverResult.Hover))

	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_ScanFile(t *testing.T) {
	hover.ClearAllHovers()
	testutil.IntegTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/RBAC.yaml")

	doc := lsp.TextDocumentItem{
		URI:        lsp.DocumentURI(path),
		LanguageID: "yaml",
		Version:    0,
	}

	dChan := make(chan lsp2.DiagnosticResult, 1)
	hoverChan := make(chan lsp2.Hover, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := cli.SnykCli{}
	go ScanFile(ctx, snykCli, doc.URI, &wg, dChan, hoverChan)
	wg.Wait()

	diagnosticResult := <-dChan
	hoverResult := <-hoverChan

	assert.NotEqual(t, 0, len(hoverResult.Hover))
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))

	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}
