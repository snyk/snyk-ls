/*
 * © 2024 Snyk Limited
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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

//nolint:dupl // not a real duplicate
func TestCLIScanner_getAbsTargetFilePathForPackageManagers(t *testing.T) {
	testutil.NotOnWindows(t, "filepaths are os dependent")
	testCases := []struct {
		name              string
		displayTargetFile string
		workDir           string
		path              string
		expected          string
	}{
		{
			name:              "NPM root directory",
			displayTargetFile: "package-lock.json",
			workDir:           "/Users/cata/git/playground/juice-shop", // if we mock the workDir
			path:              "/Users/cata/git/playground/juice-shop",
			expected:          "/Users/cata/git/playground/juice-shop/package.json",
		},
		{
			name:              "Poetry Sub Project (below the working directory)",
			displayTargetFile: "poetry-sample/pyproject.toml",
			workDir:           "/Users/cata/git/playground/python-goof",
			path:              "/Users/cata/git/playground/python-goof",
			expected:          "/Users/cata/git/playground/python-goof/poetry-sample/pyproject.toml",
		},
		{
			name:              "Gradle multi-module",
			displayTargetFile: "build.gradle",
			workDir:           "/Users/bdoetsch/workspace/gradle-multi-module",
			path:              "/Users/bdoetsch/workspace/gradle-multi-module/sample-api",
			expected:          "/Users/bdoetsch/workspace/gradle-multi-module/sample-api/build.gradle",
		},
		{
			name:              "Go Modules deeply nested",
			displayTargetFile: "build/resources/test/test-fixtures/oss/annotator/go.mod",
			workDir:           "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin",
			path:              "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin",
			expected:          "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin/build/resources/test/test-fixtures/oss/annotator/go.mod",
		},
		{
			name:              "Maven test fixtures",
			displayTargetFile: "src/test/resources/test-fixtures/oss/annotator/pom.xml",
			workDir:           "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin",
			path:              "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin",
			expected:          "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin/src/test/resources/test-fixtures/oss/annotator/pom.xml",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := getAbsTargetFilePath(
				scanResult{DisplayTargetFile: tc.displayTargetFile, Path: tc.path},
				tc.workDir,
			)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

//nolint:dupl // not a real duplicate
func TestCLIScanner_getAbsTargetFilePathForPackageManagers_Windows(t *testing.T) {
	testutil.OnlyOnWindows(t, "filepaths are os dependent")
	testCases := []struct {
		name              string
		displayTargetFile string
		workDir           string
		path              string
		expected          string
	}{
		{
			name:              "NPM root directory",
			displayTargetFile: "package-lock.json",
			workDir:           "C:\\a\\cata\\git\\playground\\juice-shop",
			path:              "C:\\a\\cata\\git\\playground\\juice-shop",
			expected:          "C:\\a\\cata\\git\\playground\\juice-shop\\package.json",
		},
		{
			name:              "Poetry Sub Project (below the working directory)",
			displayTargetFile: "poetry-sample\\pyproject.toml",
			workDir:           "C:\\a\\cata\\git\\playground\\python-goof",
			path:              "C:\\a\\cata\\git\\playground\\python-goof",
			expected:          "C:\\a\\cata\\git\\playground\\python-goof\\poetry-sample\\pyproject.toml",
		},
		{
			name:              "Gradle multi-module",
			displayTargetFile: "build.gradle",
			workDir:           "C:\\a\\bdoetsch\\workspace\\gradle-multi-module",
			path:              "C:\\a\\bdoetsch\\workspace\\gradle-multi-module\\sample-api",
			expected:          "C:\\a\\bdoetsch\\workspace\\gradle-multi-module\\sample-api\\build.gradle",
		},
		{
			name:              "Go Modules deeply nested",
			displayTargetFile: "build\\resources\\test\\test-fixtures\\oss\\annotator\\go.mod",
			workDir:           "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			path:              "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			expected:          "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin\\build\\resources\\test\\test-fixtures\\oss\\annotator\\go.mod",
		},
		{
			name:              "Maven test fixtures",
			displayTargetFile: "src\\test\\resources\\test-fixtures\\oss\\annotator\\pom.xml",
			workDir:           "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			path:              "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			expected:          "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin\\src\\test\\resources\\test-fixtures\\oss\\annotator\\pom.xml",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := getAbsTargetFilePath(
				scanResult{DisplayTargetFile: tc.displayTargetFile, Path: tc.path},
				tc.workDir,
			)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
