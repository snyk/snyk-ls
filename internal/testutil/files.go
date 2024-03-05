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

package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func CreateTempFile(t *testing.T, tempDir string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(tempDir, "")
	assert.NoError(t, err)

	t.Cleanup(func() { os.Remove(file.Name()) })
	t.Cleanup(func() { file.Close() })
	return file
}

// CreateFileOrFail creates a file in filePath with the specified content, and fails the test if there's error.
// If the path to the file doesn't exist, CreateFileOrFail will create it.
// The file does not get cleaned up, and it is the caller's responsibility to remove it.
func CreateFileOrFail(t *testing.T, filePath string, content []byte) {
	t.Helper()
	baseDir := filepath.Dir(filePath)
	err := os.MkdirAll(baseDir, 0755)
	assert.NoError(t, err)
	err = os.WriteFile(filePath, content, 0644)
	assert.NoError(t, err)
}
