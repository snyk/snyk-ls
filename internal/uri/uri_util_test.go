/*
 * ©2022-2025 Snyk Limited All rights reserved.
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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

var dir, _ = os.Getwd()

func TestPathFromUri(t *testing.T) {
	testPath := filepath.Join(dir, "asdf")
	u := PathToUri(types.FilePath(testPath))
	u = sglsp.DocumentURI(strings.Replace(string(u), "file://", "file:", 1))
	assert.Equal(t, filepath.Clean(testPath), string(PathFromUri(u))) // Eclipse case
}

func TestPathFromUri_UNC(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("testing windows UNC file paths")
	}
	uri := sglsp.DocumentURI("file://host/folder/subfolder/subsubfolder")
	res := PathFromUri(uri)
	assert.Equal(t, "\\\\host\\folder\\subfolder\\subsubfolder", string(res))
}

func TestPathToUri_UNC(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("testing windows UNC file paths")
	}
	res := PathToUri("\\\\host\\folder\\subfolder\\subsubfolder")
	assert.Equal(t, "file://host/folder/subfolder/subsubfolder", string(res))
}

func TestFolderContains(t *testing.T) {
	t.Run("Windows paths", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skipf("Windows Paths")
			return
		}
		assert.True(t, FolderContains("C:\\folder\\", "C:\\folder\\file"))
		assert.True(t, FolderContains("C:\\folder", "C:\\folder\\file"))
		assert.True(t, FolderContains("C:\\folder\\", "C:\\folder\\subfolder\\file"))
		assert.True(t, FolderContains("C:\\folder", "C:\\folder\\subfolder\\file"))
		assert.False(t, FolderContains("C:\\folder\\", "C:\\otherFolder\\file"))
		assert.False(t, FolderContains("C:\\folder", "C:\\otherFolder\\file"))
		assert.False(t, FolderContains("C:\\folder\\", "D:\\folder\\file"))
		assert.False(t, FolderContains("C:\\folder", "D:\\folder\\file"))
		assert.False(t, FolderContains("C:\\folder\\", "C:\\folder2"))
		assert.False(t, FolderContains("C:\\folder", "C:\\folder2"))
		assert.True(t, FolderContains("C:\\folder\\", "C:\\folder"))
		assert.True(t, FolderContains("C:\\folder", "C:\\folder\\"))
		assert.True(t, FolderContains("C:\\folder\\", "C:\\folder\\"))
		assert.True(t, FolderContains("C:\\Folder\\", "C:\\folder\\file"))
		assert.True(t, FolderContains("C:\\folder\\", "C:\\FOLDER\\file"))
		assert.True(t, FolderContains("C:\\FOLDER\\", "C:\\folder\\SUBFOLDER\\file"))
	})

	t.Run("POSIX paths", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skipf("POSIX Paths")
		}
		assert.True(t, FolderContains("/folder/", "/folder/file"))
		assert.True(t, FolderContains("/folder", "/folder/file"))
		assert.True(t, FolderContains("/folder/", "/folder/subfolder/file"))
		assert.True(t, FolderContains("/folder", "/folder/subfolder/file"))
		assert.False(t, FolderContains("/folder/", "/otherFolder/file"))
		assert.False(t, FolderContains("/folder", "/otherFolder/file"))
		assert.False(t, FolderContains("/folder/", "/folder2"))
		assert.False(t, FolderContains("/folder", "/folder2"))
		assert.True(t, FolderContains("/folder/", "/folder"))
		assert.True(t, FolderContains("/folder", "/folder/"))
		assert.True(t, FolderContains("/folder/", "/folder/"))
	})

	t.Run("Case sensitivity based on filesystem", func(t *testing.T) {
		tempDir := t.TempDir()
		folderPath := filepath.Join(tempDir, "TestFolder")
		filePath := filepath.Join(tempDir, "testfolder", "file.txt")
		err := os.MkdirAll(filepath.Dir(filePath), 0755)
		if err != nil {
			t.Skip("Could not create test directories")
			return
		}
		f, err := os.Create(filePath)
		if err != nil {
			t.Skip("Could not create test file")
			return
		}
		f.Close()
		isInsensitive := isCaseInsensitivePath(tempDir)
		if isInsensitive {
			assert.True(t, FolderContains(types.FilePath(folderPath), types.FilePath(filePath)), "Case-insensitive filesystem should match paths with different cases")
		} else {
			assert.False(t, FolderContains(types.FilePath(folderPath), types.FilePath(filePath)), "Case-sensitive filesystem should not match paths with different cases")
		}
	})
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

func TestUri_IsDotSnykFile(t *testing.T) {
	tests := []struct {
		name     string
		uri      sglsp.DocumentURI
		expected bool
	}{
		// POSIX paths
		{
			name:     "POSIX: file with .snyk extension",
			uri:      sglsp.DocumentURI("file:///path/to/file.snyk"),
			expected: true,
		},
		{
			name:     "POSIX: file without .snyk extension",
			uri:      sglsp.DocumentURI("file:///path/to/file.txt"),
			expected: false,
		},
		// Windows URIs
		{
			name:     "Windows URI: file with .snyk extension",
			uri:      sglsp.DocumentURI("file:///C:/path/to/file.snyk"),
			expected: true,
		},
		{
			name:     "Windows URI: URI with encoded colon and file with .snyk extension",
			uri:      sglsp.DocumentURI("file:///c%3A/Users/git/node-restify/examples/todoapp/lib/file.snyk"),
			expected: true,
		},
		{
			name:     "Windows URI: URI with encoded colon and file without .snyk extension",
			uri:      sglsp.DocumentURI("file:///c%3A/Users/git/node-restify/examples/todoapp/lib/file.txt"),
			expected: false,
		},
		// Windows paths with backslashes
		{
			name:     "Windows Path: file with .snyk extension",
			uri:      sglsp.DocumentURI("C:\\path\\to\\file.snyk"),
			expected: true,
		},
		{
			name:     "Windows URI: file without .snyk extension",
			uri:      sglsp.DocumentURI("file:///C:/path/to/file.txt"),
			expected: false,
		},
		{
			name:     "Windows Path: file without .snyk extension",
			uri:      sglsp.DocumentURI("C:\\path\\to\\file.txt"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsDotSnykFile(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsCaseInsensitivePath(t *testing.T) {
	tempDir := t.TempDir()
	result := isCaseInsensitivePath(tempDir)
	switch runtime.GOOS {
	case "windows":
		assert.True(t, result, "Windows filesystems should always be detected as case-insensitive")
	case "darwin":
		t.Log("macOS filesystem detected as case-", map[bool]string{true: "insensitive", false: "sensitive"}[result])
	default:
		assert.False(t, result, "Linux and other Unix filesystems should typically be case-sensitive")
	}
	nonExistentPath := filepath.Join(tempDir, "non_existent_dir")
	_ = isCaseInsensitivePath(nonExistentPath) // Just ensure no panic
}

func TestMacOSFileCreationFailure(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Test only applicable on macOS")
		return
	}

	// Save original os.Create function to restore later
	originalOsCreate := osCreate
	t.Cleanup(func() {
		// Restore the original os.Create function after the test completes
		osCreate = originalOsCreate
	})

	// Replace os.Create with a function that always returns an error
	osCreate = func(name string) (*os.File, error) {
		return nil, errors.New("mocked file creation error")
	}

	// Run the test with the mocked function
	tempDir := t.TempDir()
	result := isCaseInsensitivePath(tempDir)

	assert.False(t, result, "When file creation fails on macOS, the system should default to case-sensitive")
}

func getTestRange() Range {
	return Range{
		StartLine: 0,
		StartChar: 5,
		EndLine:   1,
		EndChar:   10,
	}
}

func TestIsReadableFile(t *testing.T) {
	// Create a temp file with read permission
	tmpFile, err := os.CreateTemp(t.TempDir(), "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	os.Chmod(tmpFile.Name(), 0400) // Owner read only

	if !IsRegularFile(types.FilePath(tmpFile.Name())) {
		t.Errorf("Expected true for readable file")
	}

	// Test for non-existent file
	if IsRegularFile(types.FilePath("/non/existent/file")) {
		t.Errorf("Expected false for non-existent file")
	}

	// Create a temporary directory
	tmpDir := t.TempDir()
	defer os.RemoveAll(tmpDir)

	// IsRegularFile should return false for a directory
	if IsRegularFile(types.FilePath(tmpDir)) {
		t.Errorf("Expected false for directory, got true: %s", tmpDir)
	}
}
