package oss

import (
	"os"
	"path/filepath"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/uri"
)

func TestNpmRangeFinder_Find(t *testing.T) {
	config.CurrentConfig().SetFormat(config.FormatHtml)

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

	var testPath, _ = filepath.Abs("testdata/package.json")
	var testContent, _ = os.ReadFile(testPath)

	expectedRange := sglsp.Range{
		Start: sglsp.Position{
			Line:      17,
			Character: 4,
		},
		End: sglsp.Position{
			Line:      17,
			Character: 22,
		},
	}

	actualRange := findRange(issue, uri.PathToUri(testPath), testContent)
	assert.Equal(t, expectedRange, actualRange)
}
