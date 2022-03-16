package oss

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/lsp"
)

func Test_HandleFile(t *testing.T) {
	path, content := setup()
	doc := sglsp.TextDocumentItem{
		URI:        sglsp.DocumentURI(path),
		LanguageID: "json",
		Version:    0,
		Text:       string(content),
	}
	dChan := make(chan lsp.DiagnosticResult)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go HandleFile(doc, &wg, dChan, nil)
	diagnosticResult := <-dChan
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func setup() (string, []byte) {
	environment.Load()
	environment.Format = environment.FormatHtml
	path, _ := filepath.Abs("testdata/package.json")
	content, _ := os.ReadFile(path)
	return path, content
}

func Test_introducingPackageAndVersion(t *testing.T) {
	var issue = ossIssue{
		Id:             "testIssue",
		Name:           "SNYK-TEST-ISSUE-1",
		Title:          "THOU SHALL NOT PASS",
		Severity:       "1",
		LineNumber:     0,
		Description:    "Getting into Moria is an issue!",
		References:     nil,
		Version:        "",
		PackageManager: "npm",
		From:           []string{"goof@1.0.1", "lodash@4.17.4"},
	}

	actualPackage, actualVersion := introducingPackageAndVersion(issue)
	assert.Equal(t, "4.17.4", actualVersion)
	assert.Equal(t, "lodash", actualPackage)
}

func Test_introducingPackageAndVersionJava(t *testing.T) {
	var issue = ossIssue{
		Id:             "testIssue",
		Name:           "SNYK-TEST-ISSUE-1",
		Title:          "THOU SHALL NOT PASS",
		Severity:       "1",
		LineNumber:     0,
		Description:    "Getting into Moria is an issue!",
		References:     nil,
		Version:        "",
		PackageManager: "maven",
		From:           []string{"goof@1.0.1", "a:test@4.17.4"},
	}

	actualPackage, actualVersion := introducingPackageAndVersion(issue)
	assert.Equal(t, "4.17.4", actualVersion)
	assert.Equal(t, "test", actualPackage)
}
