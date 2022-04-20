package oss

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/util"
)

func TestMavenRangeFinder_Find(t *testing.T) {
	environment.Load()
	environment.Format = environment.FormatHtml

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
		From:           []string{"goof@1.0.1", "org.apache.logging.log4j:log4j-core@2.14.1"},
	}
	var testPath, _ = filepath.Abs("testdata/pom.xml")
	var testContent, _ = os.ReadFile(testPath)

	expectedRange := lsp.Range{
		Start: lsp.Position{
			Line:      38,
			Character: 15,
		},
		End: lsp.Position{
			Line:      38,
			Character: 21,
		},
	}

	actualRange := findRange(issue, util.PathToUri(testPath), testContent)
	assert.Equal(t, expectedRange, actualRange)
}
