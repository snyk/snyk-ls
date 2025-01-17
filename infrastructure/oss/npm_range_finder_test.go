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
	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/domain/snyk"
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
	npmRangeFinder := NpmRangeFinder{
		uri:         testPath,
		fileContent: testContent,
		myRange:     snyk.Range{},
	}

	expected := ast.Node{
		Line:      17,
		StartChar: 4,
		EndChar:   22,
	}

	executeFinding(t, issue, npmRangeFinder, expected)
}

func executeFinding(t *testing.T, issue ossIssue, npmRangeFinder NpmRangeFinder, expected ast.Node) {
	t.Helper()
	p, v := introducingPackageAndVersion(issue)

	actual, _ := npmRangeFinder.find(p, v)
	assert.Equal(t, expected.Line, actual.Line)
	assert.Equal(t, expected.StartChar, actual.StartChar)
	assert.Equal(t, expected.EndChar, actual.EndChar)
}

func TestNpmRangeFinder_Find_Scoped_Packages(t *testing.T) {
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
		From:           []string{"goof@1.0.1", "@angular/cli@1.0.0"},
	}

	var testPath, _ = filepath.Abs("testdata/package.json")
	var testContent, _ = os.ReadFile(testPath)
	npmRangeFinder := NpmRangeFinder{
		uri:         testPath,
		fileContent: testContent,
		myRange:     snyk.Range{},
	}

	expected := ast.Node{
		Line:      18,
		StartChar: 4,
		EndChar:   27,
	}

	executeFinding(t, issue, npmRangeFinder, expected)
}
