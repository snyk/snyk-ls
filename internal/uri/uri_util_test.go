/*
 * Copyright 2022 Snyk Ltd.
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

package uri

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
)

var dir, _ = os.Getwd()

func TestPathFromUri(t *testing.T) {
	u := PathToUri(dir + "/asdf")
	u = lsp.DocumentURI(strings.Replace(string(u), "file://", "file:", 1))
	assert.Equal(t, filepath.Clean(dir+"/asdf"), PathFromUri(u)) // Eclipse case
}

func TestFolderContains(t *testing.T) {
	assert.True(t, FolderContains("C:/folder/", "C:/folder/file"))
	assert.True(t, FolderContains("C:/folder/", "C:/folder/subfolder/file"))
	assert.False(t, FolderContains("C:/folder/", "C:/otherFolder/file"))
	assert.False(t, FolderContains("C:/folder/", "D:/folder/file"))
}

func TestUri_AddRangeToUri(t *testing.T) {
	t.Run("range with 0 start line, should be changed to 1", func(t *testing.T) {
		r := getTestRange()
		actual := string(AddRangeToUri("file://asdf", r))
		assert.Equal(t, "file://asdf#1,6-2,11", actual)
	})
	t.Run("range with 0 end line, should be changed to 1", func(t *testing.T) {
		r := getTestRange()
		r.EndLine = 0
		actual := string(AddRangeToUri("file://asdf", r))
		assert.Equal(t, "file://asdf#1,6-1,11", actual)
	})
	t.Run("range with 0 start char, should be changed to 1", func(t *testing.T) {
		r := getTestRange()
		r.StartChar = 0
		actual := string(AddRangeToUri("file://asdf", r))
		assert.Equal(t, "file://asdf#1,1-2,11", actual)
	})
	t.Run("range with 0 end char, should be changed to 1", func(t *testing.T) {
		r := getTestRange()
		r.EndChar = 0
		actual := string(AddRangeToUri("file://asdf", r))
		assert.Equal(t, "file://asdf#1,6-2,1", actual)
	})
	t.Run("range ending with `/` should not be changed", func(t *testing.T) {
		r := getTestRange()
		actual := string(AddRangeToUri("file://asdf/", r))
		assert.Equal(t, "file://asdf/", actual)
	})
	t.Run("range already having a location fragment should not be changed", func(t *testing.T) {
		r := getTestRange()
		actual := string(AddRangeToUri("file://asdf#L1,1-L1,1", r))
		assert.Equal(t, "file://asdf#L1,1-L1,1", actual)
	})
}

func getTestRange() Range {
	r := Range{
		StartLine: 0,
		StartChar: 5,
		EndLine:   1,
		EndChar:   10,
	}
	return r
}
