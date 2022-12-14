/*
 * © 2022 Snyk Limited All rights reserved.
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

package util

import (
	"os"
	"testing"

	ignore "github.com/sabhiram/go-gitignore"
	"github.com/stretchr/testify/assert"
)

func Test_ignored_ignoredGlob(t *testing.T) {
	ignoredPath := "test.xml"

	err := os.WriteFile(ignoredPath, []byte("test"), 0600)
	defer func(path string) { _ = os.RemoveAll(path) }(ignoredPath)
	if err != nil {
		t.Fatal(err, "Couldn't create file "+ignoredPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}

	assert.True(t, Ignored(ignore.CompileIgnoreLines(patterns...), ignoredPath))
}

func Test_ignored_notIgnored(t *testing.T) {
	notIgnoredPath := "not-ignored.txt"
	err := os.WriteFile(notIgnoredPath, []byte("test"), 0600)
	defer func(path string) { _ = os.RemoveAll(path) }(notIgnoredPath)
	if err != nil {
		t.Fatal(err, "Couldn't create file "+notIgnoredPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}

	assert.False(t, Ignored(ignore.CompileIgnoreLines(patterns...), notIgnoredPath))
}

func Test_ignored_doubleAsterisk(t *testing.T) {
	ignoredDoubleAsteriskPath := "test-ignore/ignored.txt"
	testIgnoreDir := "test-ignore"
	err := os.Mkdir(testIgnoreDir, 0755)
	defer func(path string) { _ = os.RemoveAll(path) }(testIgnoreDir)
	if err != nil {
		t.Fatal(err, "Couldn't create testIgnoreDir"+testIgnoreDir)
	}
	err = os.WriteFile(ignoredDoubleAsteriskPath, []byte("test"), 0600)
	defer func(path string) { _ = os.RemoveAll(path) }(ignoredDoubleAsteriskPath)
	if err != nil {
		t.Fatal(err, "Couldn't create file "+ignoredDoubleAsteriskPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}
	assert.True(t, Ignored(ignore.CompileIgnoreLines(patterns...), ignoredDoubleAsteriskPath))
}
