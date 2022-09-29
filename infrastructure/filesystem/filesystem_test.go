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

package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLineOfCode(t *testing.T) {
	t.Run("correct line", func(t *testing.T) {
		fileName := setupCodeFile(t)
		f := New()

		actual, err := f.GetLineOfCode(fileName, 3)

		assert.NoError(t, err)
		assert.Equal(t, "Line3", actual)
	})
	t.Run("above maximum line number should cause err", func(t *testing.T) {
		fileName := setupCodeFile(t)
		f := New()

		actual, err := f.GetLineOfCode(fileName, 5)
		assert.Error(t, err)
		assert.Equal(t, "", actual)
	})
	t.Run("negative line number should cause err", func(t *testing.T) {
		fileName := setupCodeFile(t)
		f := New()

		actual, err := f.GetLineOfCode(fileName, -1)
		assert.Error(t, err)
		assert.Equal(t, "", actual)
	})
	t.Run("0 line number should cause err", func(t *testing.T) {
		fileName := setupCodeFile(t)
		f := New()

		actual, err := f.GetLineOfCode(fileName, 0)
		assert.Error(t, err)
		assert.Equal(t, "", actual)
	})
}

func setupCodeFile(t *testing.T) string {
	dir := t.TempDir()
	fileName := filepath.Join(dir, "testFile")
	err := os.WriteFile(fileName, []byte("Line1\nLine2\nLine3\nLine4"), 0660)
	if err != nil {
		t.Fatal(err, "Couldn't create test file")
	}
	return fileName
}
