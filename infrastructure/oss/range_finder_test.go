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

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_DefaultFinder_FindRange(t *testing.T) {
	engine := testutil.UnitTest(t)
	issue, testPath, testContent := setupDefaultFinderEnvForTesting()
	expectedRange := getExpectedRangeForDefaultFinderTests()

	actualRange := getDependencyNode(engine.GetLogger(), testPath, issue.PackageManager, [][]string{issue.From}, testContent, "")

	assert.Equal(t, expectedRange, getRangeFromNode(actualRange))
}

func TestDefaultFinder_Find(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingFormat), config.FormatHtml)

	issue, testPath, testContent := setupDefaultFinderEnvForTesting()

	defaultFinder := DefaultFinder{
		path:        testPath,
		fileContent: testContent,
		logger:      engine.GetLogger(),
	}

	expectedRange := getExpectedRangeForDefaultFinderTests()

	p, v := introducingPackageAndVersion(issue.From, issue.PackageManager)

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

func Test_DefaultFinder_Go_SubPackageResolvesToContainingModule(t *testing.T) {
	engine := testutil.UnitTest(t)
	content := []byte("module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gofiber/fiber/v2 v2.50.0\n\tgithub.com/gofiber/swagger v0.1.14\n)\n")

	tests := []struct {
		name         string
		from         []string
		expectedLine int
	}{
		{"sub-package maps to its module", []string{"example.com/app@0.0.0", "github.com/gofiber/fiber/v2/middleware/cors@2.50.0"}, 5},
		{"module maps to itself", []string{"example.com/app@0.0.0", "github.com/gofiber/swagger@0.1.14", "github.com/gofiber/fiber/v2/utils@2.50.0"}, 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := getDependencyNode(engine.GetLogger(), "go.mod", "gomodules", [][]string{tt.from}, content, "")
			assert.NotNil(t, node)
			assert.Equal(t, tt.expectedLine, node.Line)
		})
	}
}

func Test_GetDependencyNode_Go_PrefersDependencyContainingThePackage(t *testing.T) {
	engine := testutil.UnitTest(t)
	content := []byte("module example.com/app\n\nrequire (\n\tgithub.com/gofiber/fiber/v2 v2.50.0\n\tgithub.com/gofiber/swagger v0.1.14\n)\n")
	paths := [][]string{
		{"example.com/app@0.0.0", "github.com/gofiber/swagger@0.1.14", "github.com/gofiber/fiber/v2/utils@2.50.0"},
		{"example.com/app@0.0.0", "github.com/gofiber/fiber/v2@2.50.0", "github.com/gofiber/fiber/v2/utils@2.50.0"},
		{"example.com/app@0.0.0", "github.com/gofiber/swagger@0.1.14", "github.com/gofiber/fiber/v2/middleware/filesystem@2.50.0", "github.com/gofiber/fiber/v2/utils@2.50.0"},
	}
	reversed := [][]string{paths[2], paths[1], paths[0]}

	node := getDependencyNode(engine.GetLogger(), "go.mod", "gomodules", paths, content, "")
	nodeFromReversedOrder := getDependencyNode(engine.GetLogger(), "go.mod", "gomodules", reversed, content, "")

	assert.Equal(t, node.Line, nodeFromReversedOrder.Line)

	assert.NotNil(t, node)
	assert.Equal(t, 3, node.Line)
}

func Test_GetDependencyNode_NonGo_UsesFirstPath(t *testing.T) {
	engine := testutil.UnitTest(t)
	content := []byte("{\n  \"dependencies\": {\n    \"errorhandler\": \"1.2.0\",\n    \"st\": \"0.2.4\"\n  }\n}\n")
	paths := [][]string{
		{"goof@1.0.1", "errorhandler@1.2.0", "negotiator@0.4.9"},
		{"goof@1.0.1", "st@0.2.4", "negotiator@0.2.8"},
	}

	node := getDependencyNode(engine.GetLogger(), "package.json", "npm", paths, content, "")

	assert.NotNil(t, node)
	assert.Equal(t, 2, node.Line)
}

func Test_GroupVulnerabilities_KeepsFirstIssueAndAllPaths(t *testing.T) {
	engine := testutil.UnitTest(t)
	first := ossIssue{Id: "A", PackageName: "p", Version: "1", From: []string{"root", "x", "p"}}
	second := ossIssue{Id: "A", PackageName: "p", Version: "2", From: []string{"root", "p"}}
	ignored := ossIssue{Id: "B", PackageName: "p", From: []string{"root", "p"}, IsIgnored: true}

	groups := groupVulnerabilities([]ossIssue{first, second, ignored}, engine.GetLogger())

	assert.Len(t, groups, 1)
	assert.Equal(t, first.Version, groups[0].issue.Version)
	assert.Equal(t, [][]string{first.From, second.From}, groups[0].dependencyPaths)
}
