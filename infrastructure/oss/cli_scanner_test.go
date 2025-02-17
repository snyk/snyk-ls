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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestCLIScanner_getAbsTargetFilePathForPackageManagers(t *testing.T) {
	testCases := []struct {
		name                       string
		displayTargetFile          string
		workDir                    string
		displayTargetFileInWorkDir string
		path                       string
		expected                   string
	}{
		{
			name:              "NPM root directory",
			displayTargetFile: "package-lock.json",
			workDir:           "/Users/cata/git/playground/juice-shop", // if we mock the workDir
			path:              "/Users/cata/git/playground/juice-shop",
			expected:          "/Users/cata/git/playground/juice-shop/package.json",
		},
		{
			name:                       "NPM sub directory",
			displayTargetFile:          "frontend/package.json",
			displayTargetFileInWorkDir: "package.json",
			workDir:                    "/Users/cata/git/playground/juice-shop", // if we mock the workDir
			path:                       "/Users/cata/git/playground/juice-shop",
			expected:                   "/Users/cata/git/playground/juice-shop/frontend/package.json",
		},
		{
			name:              "Poetry Sub Project (below the working directory)",
			displayTargetFile: "poetry-sample/pyproject.toml",
			workDir:           "/Users/cata/git/playground/python-goof",
			path:              "/Users/cata/git/playground/python-goof",
			expected:          "/Users/cata/git/playground/python-goof/poetry-sample/pyproject.toml",
		},
		{
			name:                       "Gradle multi-module",
			displayTargetFile:          "build.gradle",
			displayTargetFileInWorkDir: "build.gradle",
			workDir:                    "/Users/bdoetsch/workspace/gradle-multi-module",
			path:                       "/Users/bdoetsch/workspace/gradle-multi-module/sample-api",
			expected:                   "/Users/bdoetsch/workspace/gradle-multi-module/sample-api/build.gradle",
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
		{
			name:              "Gemfile deep below working dir",
			displayTargetFile: ".bin/pact/lib/vendor/Gemfile.lock",
			workDir:           "/Users/bdoetsch/workspace/snyk-ls",
			path:              "/Users/bdoetsch/workspace/snyk-ls/.bin/pact/lib/vendor",
			expected:          "/Users/bdoetsch/workspace/snyk-ls/.bin/pact/lib/vendor/Gemfile",
		},
		{
			name:              "(win) NPM root directory",
			displayTargetFile: "package-lock.json",
			workDir:           "C:\\a\\cata\\git\\playground\\juice-shop",
			path:              "C:\\a\\cata\\git\\playground\\juice-shop",
			expected:          "C:\\a\\cata\\git\\playground\\juice-shop\\package.json",
		},
		{
			name:              "(win) Poetry Sub Project (below the working directory)",
			displayTargetFile: "poetry-sample\\pyproject.toml",
			workDir:           "C:\\a\\cata\\git\\playground\\python-goof",
			path:              "C:\\a\\cata\\git\\playground\\python-goof",
			expected:          "C:\\a\\cata\\git\\playground\\python-goof\\poetry-sample\\pyproject.toml",
		},
		{
			name:              "(win) Gradle multi-module",
			displayTargetFile: "build.gradle",
			workDir:           "C:\\a\\bdoetsch\\workspace\\gradle-multi-module",
			path:              "C:\\a\\bdoetsch\\workspace\\gradle-multi-module\\sample-api",
			expected:          "C:\\a\\bdoetsch\\workspace\\gradle-multi-module\\sample-api\\build.gradle",
		},
		{
			name:              "(win) Go Modules deeply nested",
			displayTargetFile: "build\\resources\\test\\test-fixtures\\oss\\annotator\\go.mod",
			workDir:           "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			path:              "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			expected:          "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin\\build\\resources\\test\\test-fixtures\\oss\\annotator\\go.mod",
		},
		{
			name:              "(win) Maven test fixtures",
			displayTargetFile: "src\\test\\resources\\test-fixtures\\oss\\annotator\\pom.xml",
			workDir:           "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			path:              "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			expected:          "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin\\src\\test\\resources\\test-fixtures\\oss\\annotator\\pom.xml",
		},
		{
			name:              "(win) Gemfile deep below working dir",
			displayTargetFile: ".bin\\pact\\lib\\vendor\\Gemfile.lock",
			workDir:           "C:\\Users\\bdoetsch\\workspace\\snyk-ls",
			path:              "C:\\Users\\bdoetsch\\workspace\\snyk-ls\\.bin\\pact\\lib\\vendor",
			expected:          "C:\\Users\\bdoetsch\\workspace\\snyk-ls\\.bin\\pact\\lib\\vendor\\Gemfile",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			skipReason := "filepath is os dependent"
			prefix := "C:"
			if strings.HasPrefix(tc.workDir, prefix) {
				testsupport.OnlyOnWindows(t, skipReason)
			} else {
				testsupport.NotOnWindows(t, skipReason)
			}

			base := t.TempDir()
			adjustedExpected, _ := strings.CutPrefix(tc.expected, prefix)
			adjustedWorkDir, _ := strings.CutPrefix(tc.workDir, prefix)
			adjustedPath, _ := strings.CutPrefix(tc.path, prefix)
			expected := filepath.Join(base, adjustedExpected)
			dir := filepath.Dir(expected)
			require.NoError(t, os.MkdirAll(dir, 0770))
			require.NoError(t, os.WriteFile(expected, []byte(expected), 0666))
			if tc.displayTargetFileInWorkDir != "" {
				absFile := filepath.Join(base, adjustedWorkDir, tc.displayTargetFileInWorkDir)
				require.NoError(t, os.WriteFile(absFile, []byte(tc.displayTargetFileInWorkDir), 0666))
			}

			actual := getAbsTargetFilePath(c, scanResult{
				DisplayTargetFile: tc.displayTargetFile,
				Path:              filepath.Join(base, adjustedPath),
			}, types.FilePath(filepath.Join(base, adjustedWorkDir)), types.FilePath(filepath.Join(base, adjustedPath)))
			assert.Equal(t, expected, actual)
		})
	}
}
