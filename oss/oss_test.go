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

func Test_ScanWorkspace(t *testing.T) {
	environment.Load()
	environment.Format = environment.FormatHtml

	path, _ := filepath.Abs("testdata")

	doc := sglsp.DocumentURI(path)

	dChan := make(chan lsp.DiagnosticResult)
	wg := sync.WaitGroup{}
	wg.Add(1)

	go ScanWorkspace(doc, &wg, dChan, nil)

	diagnosticResult := <-dChan

	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_ScanFile(t *testing.T) {
	environment.Load()
	environment.Format = environment.FormatHtml

	path, _ := filepath.Abs("testdata/package.json")
	content, _ := os.ReadFile(path)

	doc := sglsp.TextDocumentItem{
		URI:        sglsp.DocumentURI(path),
		LanguageID: "json",
		Version:    0,
		Text:       string(content),
	}

	dChan := make(chan lsp.DiagnosticResult)
	wg := sync.WaitGroup{}
	wg.Add(1)

	go ScanFile(doc, &wg, dChan, nil)

	diagnosticResult := <-dChan

	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
}

func Test_FindRange(t *testing.T) {
	issue := mavenTestIssue()
	content := "0\n1\n2\n  implementation 'a:test:4.17.4'"

	doc := sglsp.TextDocumentItem{URI: "file://build.gradle", LanguageID: "groovy", Text: content}
	foundRange := findRange(issue, doc)

	assert.Equal(t, 3, foundRange.Start.Line)
	assert.Equal(t, 20, foundRange.Start.Character)
	assert.Equal(t, 31, foundRange.End.Character)
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
	issue := mavenTestIssue()

	actualPackage, actualVersion := introducingPackageAndVersion(issue)
	assert.Equal(t, "4.17.4", actualVersion)
	assert.Equal(t, "test", actualPackage)
}

func mavenTestIssue() ossIssue {
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

	return issue
}
