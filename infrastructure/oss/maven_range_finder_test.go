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
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestMavenRangeFinder_Find(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetFormat(config.FormatHtml)

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

	finder := mavenRangeFinder{
		path:        testPath,
		fileContent: testContent,
		c:           c,
	}

	expected := ast.Node{
		Line:      54,
		StartChar: 15,
		EndChar:   21,
	}

	p, v := introducingPackageAndVersion(issue)

	actual := finder.find(p, v)
	assert.Equal(t, expected.Line, actual.Line)
	assert.Equal(t, expected.StartChar, actual.StartChar)
	assert.Equal(t, expected.EndChar, actual.EndChar)

}

func TestMavenRangeFinder_FindInPomHierarchy(t *testing.T) {
	c := testutil.UnitTest(t)
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
		From:           []string{"goof@1.0.1", "commons-fileupload:commons-fileupload@1.2.1"},
	}
	var testPath, _ = filepath.Abs("testdata/maven-goof/sub/pom.xml")
	var testContent, _ = os.ReadFile(testPath)

	finder := mavenRangeFinder{
		path:        testPath,
		fileContent: testContent,
		c:           c,
	}

	expected := ast.Node{
		Line:      35,
		StartChar: 18,
		EndChar:   36,
	}

	p, v := introducingPackageAndVersion(issue)

	actual := finder.find(p, v)
	assert.Equal(t, expected.Line, actual.Line)
	assert.Equal(t, expected.StartChar, actual.StartChar)
	assert.Equal(t, expected.EndChar, actual.EndChar)

}
