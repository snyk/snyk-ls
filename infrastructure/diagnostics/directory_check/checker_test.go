/*
 * © 2026 Snyk Limited All rights reserved.
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

package directory_check

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
)

var nopLogger = zerolog.Nop()

var testSnykBinaries = []string{
	"snyk-linux",
	"snyk-macos",
	"snyk-win.exe",
	"snyk-alpine",
	"snyk-linux-arm64",
}

// ----------------------------------
// Unit Tests for Exported Functions
// ----------------------------------

func Test_GetDefaultUsedDirectories(t *testing.T) {
	testutil.UnitTest(t)

	dirs := GetDefaultUsedDirectories(&nopLogger)

	// Should always return at least some directories
	assert.NotEmpty(t, dirs, "Should return at least one directory")

	// Check for platform-specific directories
	switch runtime.GOOS {
	case "windows":
		// Should include Windows-specific paths
		hasWindowsPath := false
		for _, dir := range dirs {
			if strings.Contains(dir.PathWanted, "AppData") || strings.Contains(dir.PathWanted, "Local") {
				hasWindowsPath = true
				break
			}
		}
		assert.True(t, hasWindowsPath, "Should include Windows-specific paths")
	case "darwin", "linux":
		// Should include Unix-style paths
		hasUnixPath := false
		for _, dir := range dirs {
			if strings.Contains(dir.PathWanted, ".local") || strings.Contains(dir.PathWanted, "Library") || strings.Contains(dir.PathWanted, ".snyk") {
				hasUnixPath = true
				break
			}
		}
		assert.True(t, hasUnixPath, "Should include Unix-style paths")
	}

	// All directories should have descriptions
	for _, dir := range dirs {
		assert.NotEmpty(t, dir.Purpose, "Each directory should have a description")
	}
}

func Test_DedupeDirectories_CombinesPurposesAndMayContainCLI(t *testing.T) {
	testutil.UnitTest(t)

	dirs := []UsedDirectory{
		{PathWanted: "/path/one", Purpose: "First Purpose", MayContainCLI: false},
		{PathWanted: "/path/two", Purpose: "Second Purpose", MayContainCLI: true},
		{PathWanted: "/path/one", Purpose: "Another Purpose", MayContainCLI: true}, // Duplicate, has CLI
		{PathWanted: "/path/three", Purpose: "Third Purpose", MayContainCLI: false},
		{PathWanted: "/path/two", Purpose: "Yet Another Purpose", MayContainCLI: false}, // Duplicate, no CLI
		{PathWanted: "/path/four", Purpose: "Fourth Purpose", MayContainCLI: true},
		{PathWanted: "/path/four", Purpose: "More Fourth", MayContainCLI: true}, // Duplicate, both have CLI
	}

	result := DedupeDirectories(dirs)

	// Should have 4 unique paths
	require.Len(t, result, 4, "Should deduplicate to 4 unique paths")

	// Verify order is preserved (first occurrence)
	require.Equal(t, "/path/one", result[0].PathWanted, "First unique path should be /path/one")
	require.Equal(t, "/path/two", result[1].PathWanted, "Second unique path should be /path/two")
	require.Equal(t, "/path/three", result[2].PathWanted, "Third unique path should be /path/three")
	require.Equal(t, "/path/four", result[3].PathWanted, "Fourth unique path should be /path/four")

	// Check /path/one, MayContainCLI = false + true -> true
	assert.Equal(t, "First Purpose & Another Purpose", result[0].Purpose, "Should combine purposes for /path/one")
	assert.True(t, result[0].MayContainCLI, "Should be true if any duplicate has MayContainCLI true")

	// Check /path/two, MayContainCLI = true + false -> true
	assert.Equal(t, "Second Purpose & Yet Another Purpose", result[1].Purpose, "Should combine purposes for /path/two")
	assert.True(t, result[1].MayContainCLI, "Should stay true even if duplicate has false")

	// Check /path/three, MayContainCLI = false only -> false
	assert.Equal(t, "Third Purpose", result[2].Purpose, "Should keep single purpose for /path/three")
	assert.False(t, result[2].MayContainCLI, "Should be false when no duplicates have true")

	// Check /path/four, MayContainCLI = true + true -> true
	assert.Equal(t, "Fourth Purpose & More Fourth", result[3].Purpose, "Should combine purposes for /path/four")
	assert.True(t, result[3].MayContainCLI, "Should be true when all have true")
}

func Test_GetCurrentUser_ReturnsNonEmpty(t *testing.T) {
	testutil.UnitTest(t)

	user := GetCurrentUser()

	assert.NotEmpty(t, user, "Should return a non-empty user")
}

// -----------------------------------------
// Unit Tests for Internal Helper Functions
// -----------------------------------------

func Test_findParentDirectory_FindsExistingParent(t *testing.T) {
	testutil.UnitTest(t)

	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "does-not-exist", "nested", "path")

	parent := findParentDirectory(nonExistentPath)

	assert.Equal(t, tmpDir, parent, "Parent should be the temp directory")
}

func Test_findParentDirectory_NonExistentRootLevelPath(t *testing.T) {
	testutil.UnitTest(t)

	var nonExistentPath string
	var expectedParent string
	if runtime.GOOS == "windows" {
		nonExistentPath = "C:\\non-existent\\path"
		expectedParent = "C:\\"
	} else {
		nonExistentPath = "/non-existent/path"
		expectedParent = "/"
	}

	parent := findParentDirectory(nonExistentPath)

	assert.Equal(t, expectedParent, parent, "Should go up to the root level without issues / errors")
}

func Test_findCLIBinaries_EmptyDirectory(t *testing.T) {
	testutil.UnitTest(t)

	tmpDir := t.TempDir()

	found := findCLIBinaries(tmpDir)

	assert.Empty(t, found, "Should find no binaries in empty directory")
}

func Test_findCLIBinaries_FindsSnykExecutables(t *testing.T) {
	testutil.UnitTest(t)

	tmpDir := t.TempDir()
	createTestBinaries(t, tmpDir)
	createNonBinaryTestFile(t, tmpDir)

	found := findCLIBinaries(tmpDir)

	require.Len(t, found, len(testSnykBinaries), "Should find all Snyk binaries")

	// Verify all binaries have required fields
	for _, bin := range found {
		assert.NotEmpty(t, bin.Name, "Binary should have a name")
		assert.NotEmpty(t, bin.Permissions, "Binary should have permissions")
	}
}

func Test_findCLIBinaries_FiltersTmpFiles(t *testing.T) {
	testutil.UnitTest(t)

	tmpDir := t.TempDir()

	// Create real binaries
	createTestBinaries(t, tmpDir)

	// Create .tmp files that should be filtered out
	tmpFile := filepath.Join(tmpDir, "snyk-macos-arm6410013701423949607140.tmp")
	err := os.WriteFile(tmpFile, []byte("binary"), 0744)
	require.NoError(t, err)

	// Create non-binary file
	createNonBinaryTestFile(t, tmpDir)

	found := findCLIBinaries(tmpDir)

	// Should only find the real binaries, not .tmp files
	require.Len(t, found, len(testSnykBinaries), "Should find only actual Snyk binaries, not .tmp files")

	// Verify no .tmp files included
	for _, bin := range found {
		assert.False(t, strings.HasSuffix(bin.Name, ".tmp"), "Should not include .tmp files")
	}
}

func Test_isProbablySnykCLI_FiltersTmpFiles(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name     string
		fileName string
		want     bool
	}{
		{"Valid binary no extension", "snyk-macos-arm64", true},
		{"Valid binary linux", "snyk-linux", true},
		{"Valid exe", "snyk.exe", true},
		{"Valid win exe", "snyk-win.exe", true},
		{"Plain snyk", "snyk", true},
		{"Tmp file with valid prefix", "snyk-macos-arm6410013701423949607140.tmp", false},
		{"Tmp file uppercase", "snyk-macos.TMP", false},
		{"Log file", "snyk-mcp.log", false},
		{"JSON file", "snyk-data.json", false},
		{"Text file", "snyk.txt", false},
		{"Non-snyk file", "other-file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProbablySnykCLI(tt.fileName)
			assert.Equal(t, tt.want, got)
		})
	}
}

// -------------------------------------
// Integration tests for CheckDirectory
// -------------------------------------

func Test_CheckDirectory_ExistingWritableDirectory(t *testing.T) {
	testutil.UnitTest(t)

	tmpDir := t.TempDir()

	result := CheckDirectory(UsedDirectory{PathWanted: tmpDir, Purpose: "Test Directory"})

	assert.Empty(t, result.Error, "Should not have an error")
	assert.Equal(t, tmpDir, result.PathWanted, "PathWanted should be the requested directory")
	assert.Equal(t, tmpDir, result.PathFound, "PathFound should be the requested directory")
	assert.True(t, result.IsWritable, "Directory should be writable")
	assert.NotEmpty(t, result.Permissions, "Should have permissions")
}

func Test_CheckDirectory_NonExistentDirectory(t *testing.T) {
	testutil.UnitTest(t)

	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "does-not-exist", "nested", "path")

	result := CheckDirectory(UsedDirectory{PathWanted: nonExistentPath, Purpose: "Test Non-Existent"})

	assert.Equal(t, nonExistentPath, result.PathWanted, "PathWanted should be the requested path")
	assert.Equal(t, "Test Non-Existent", result.Purpose, "Should have correct description")
	assert.Equal(t, tmpDir, result.PathFound, "PathFound should be the existing parent temp directory")
	assert.NotEmpty(t, result.Permissions, "Should have permissions info for the existing parent temp directory")
	assert.True(t, result.IsWritable, "Existing parent temp directory should be writable")
}

func Test_CheckDirectory_WithCLIBinaries(t *testing.T) {
	testutil.UnitTest(t)

	tmpDir := t.TempDir()
	createTestBinaries(t, tmpDir)

	result := CheckDirectory(UsedDirectory{PathWanted: tmpDir, Purpose: "Test With Binaries", MayContainCLI: true})

	assert.Equal(t, result.PathWanted, result.PathFound, "PathFound should equal PathWanted")
	assert.Equal(t, "Test With Binaries", result.Purpose, "Should have correct description")
	require.Len(t, result.BinariesFound, len(testSnykBinaries), "Should find all CLI binaries")

	// Verify all binaries have required fields
	for _, bin := range result.BinariesFound {
		assert.NotEmpty(t, bin.Name, "Binary should have a name")
		assert.NotEmpty(t, bin.Permissions, "Binary should have permissions")
	}
}

func Test_CheckDirectory_PermissionsFormat(t *testing.T) {
	testutil.UnitTest(t)

	tmpDir := t.TempDir()

	result := CheckDirectory(UsedDirectory{PathWanted: tmpDir, Purpose: "Test Permissions"})

	assert.Equal(t, result.PathWanted, result.PathFound, "PathFound should equal PathWanted")
	assert.Equal(t, "Test Permissions", result.Purpose, "Should have correct description")
	assert.Regexp(t, `^0[0-7]{3}$`, result.Permissions, "Permissions should be in octal format, e.g. 0755")
}

func Test_CheckDirectory_ReadOnlyDirectory(t *testing.T) {
	testutil.UnitTest(t)

	if runtime.GOOS == "windows" {
		t.Skip("Skipping read-only test on Windows")
	}

	tmpDir := t.TempDir()

	// Make directory read-only
	err := os.Chmod(tmpDir, 0555)
	require.NoError(t, err)

	// Clean up: restore write permissions
	t.Cleanup(func() {
		err = os.Chmod(tmpDir, 0755)
		require.NoError(t, err)
	})

	result := CheckDirectory(UsedDirectory{PathWanted: tmpDir, Purpose: "Test Read-Only"})

	assert.Equal(t, result.PathWanted, result.PathFound, "PathFound should equal PathWanted")
	assert.Equal(t, "Test Read-Only", result.Purpose, "Should have correct description")
	assert.False(t, result.IsWritable, "Directory should not be writable")
}

// -------------------------------------
// Test for RunDiagnostics
// -------------------------------------

func Test_RunDiagnostics_ReturnsResults(t *testing.T) {
	testutil.UnitTest(t)

	result := RunDiagnostics(&nopLogger, nil)

	assert.NotEmpty(t, result.CurrentUser, "Should have current user")
	assert.NotEmpty(t, result.DirectoryResults, "Should have directory results")
}

func Test_RunDiagnostics_WithAdditionalDirs(t *testing.T) {
	testutil.UnitTest(t)

	tmpDir := t.TempDir()
	additionalDirs := []UsedDirectory{
		{PathWanted: tmpDir, Purpose: "Test Additional Directory", MayContainCLI: false},
	}

	result := RunDiagnostics(&nopLogger, additionalDirs)

	// Should include our additional directory
	found := false
	for _, dirResult := range result.DirectoryResults {
		if dirResult.PathWanted == tmpDir {
			found = true
			assert.Equal(t, "Test Additional Directory", dirResult.Purpose)
			break
		}
	}
	assert.True(t, found, "Should include the additional directory in results")
}

// ----------------------
// Test helper functions
// ----------------------

// createTestBinaries creates mock Snyk CLI binaries in the given directory
func createTestBinaries(t *testing.T, dir string) {
	t.Helper()
	for _, name := range testSnykBinaries {
		binPath := filepath.Join(dir, name)
		err := os.WriteFile(binPath, []byte("mock"), 0755)
		require.NoError(t, err)
	}
}

// createNonBinaryTestFile creates a non-CLI binary file that should be ignored in the given directory
func createNonBinaryTestFile(t *testing.T, dir string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, "other-file.txt"), []byte("text"), 0644)
	require.NoError(t, err)
}
