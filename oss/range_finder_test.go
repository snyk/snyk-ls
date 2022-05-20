package oss

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

func TestDefaultFinder_Find(t *testing.T) {
	testutil.UnitTest(t)
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
		PackageManager: "golang",
		From:           []string{"goof@1.0.1", "github.com/gin-gonic/gin@1.4.0"},
	}
	var testPath, _ = filepath.Abs("testdata/go.mod")
	var testContent, _ = os.ReadFile(testPath)

	expectedRange := lsp.Range{
		Start: lsp.Position{
			Line:      9,
			Character: 1,
		},
		End: lsp.Position{
			Line:      9,
			Character: 32,
		},
	}

	actualRange := findRange(issue, uri.PathToUri(testPath), testContent)
	assert.Equal(t, expectedRange, actualRange)
}
