/*
 * © 2022-2023 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package oss

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_DefaultFinder_FindRange(t *testing.T) {
	c := testutil.UnitTest(t)
	issue, testPath, testContent := setupDefaultFinderEnvForTesting()
	expectedRange := getExpectedRangeForDefaultFinderTests()

	actualRange := getDependencyNode(c, testPath, issue, testContent)

	assert.Equal(t, expectedRange, getRangeFromNode(actualRange))
}

func TestDefaultFinder_Find(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetFormat(config.FormatHtml)

	issue, testPath, testContent := setupDefaultFinderEnvForTesting()

	defaultFinder := DefaultFinder{
		path:        testPath,
		fileContent: testContent,
		c:           c,
	}

	expectedRange := getExpectedRangeForDefaultFinderTests()

	p, v := introducingPackageAndVersion(issue)

	actualRange, _ := defaultFinder.find(p, v)
	assert.Equal(t, expectedRange, getRangeFromNode(actualRange))
}

func getExpectedRangeForDefaultFinderTests() types.Range {
	expectedRange := types.Range{
		Start: types.Position{
			Line:      9,
			Character: 1,
		},
		End: types.Position{
			Line:      9,
			Character: 32,
		},
	}
	return expectedRange
}

func setupDefaultFinderEnvForTesting() (ossIssue, types.FilePath, []byte) {
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
	return issue, types.FilePath(testPath), testContent
}
