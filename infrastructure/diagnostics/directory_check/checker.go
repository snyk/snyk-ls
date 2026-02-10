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

// Package directory_check provides diagnostics for checking Snyk-related directories
// including CLI download locations, config storage, and cache directories.
package directory_check

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rs/zerolog"
)

// RunDiagnostics runs directory diagnostics and returns the result
func RunDiagnostics(logger *zerolog.Logger, additionalDirs []UsedDirectory) *DiagnosticsResult {
	result := &DiagnosticsResult{
		CurrentUser: GetCurrentUser(),
	}

	// Get default directories
	dirs := GetDefaultUsedDirectories(logger)

	// Add additional directories
	dirs = append(dirs, additionalDirs...)

	// Deduplicate
	dirs = DedupeDirectories(dirs)

	// Check each directory
	for _, dir := range dirs {
		dirResult := CheckDirectory(dir)
		result.DirectoryResults = append(result.DirectoryResults, dirResult)
	}

	return result
}

// GetDefaultUsedDirectories returns the default directories used by Snyk (CLI, config, cache)
func GetDefaultUsedDirectories(logger *zerolog.Logger) []UsedDirectory {
	var dirs []UsedDirectory

	// Get home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}

	// Platform-specific paths
	switch runtime.GOOS {
	case "windows":
		dirs = append(dirs, getUsedDirectoriesWindows(homeDir)...)
	case "darwin", "linux":
		dirs = append(dirs, getUsedDirectoriesUnix(homeDir)...)
	default:
		logger.Warn().Str("os", runtime.GOOS).Msg("Unknown operating system for CLI directory detection")
	}

	// Common paths for all platforms

	// In the user's cache directory
	cacheDir, err := os.UserCacheDir()
	if err == nil && cacheDir != "" {
		dirs = append(dirs, UsedDirectory{
			PathWanted:    filepath.Join(cacheDir, "snyk", "snyk-cli"),
			Purpose:       "Runtime Cache for Temporary Files",
			MayContainCLI: false,
		})
	}

	return dirs
}

// getUsedDirectoriesWindows returns Windows-specific directories used by Snyk
func getUsedDirectoriesWindows(homeDir string) []UsedDirectory {
	var dirs []UsedDirectory

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" && homeDir != "" {
		localAppData = filepath.Join(homeDir, "AppData", "Local")
	}

	if localAppData != "" {
		// VS Code Extension location
		dirs = append(dirs, UsedDirectory{
			PathWanted:    filepath.Join(localAppData, "snyk", "vscode-cli"),
			Purpose:       "Default CLI Download Location for VS Code Extension",
			MayContainCLI: true,
		})
		// Eclipse Plugin & Visual Studio Plugin location
		dirs = append(dirs, UsedDirectory{
			PathWanted:    filepath.Join(localAppData, "Snyk"),
			Purpose:       "Default CLI Download Location for Eclipse Plugin and Visual Studio Plugin",
			MayContainCLI: true,
		})
		// Language Server config location
		dirs = append(dirs, UsedDirectory{
			PathWanted:    filepath.Join(localAppData, "snyk"),
			Purpose:       "Language Server Config Storage",
			MayContainCLI: false,
		})
	}

	return dirs
}

// getUsedDirectoriesUnix returns Unix-like (macOS and Linux) directories used by Snyk
func getUsedDirectoriesUnix(homeDir string) []UsedDirectory {
	var dirs []UsedDirectory

	if homeDir != "" && runtime.GOOS == "darwin" {
		// VS Code Extension location (on Darwin only)
		dirs = append(dirs, UsedDirectory{
			PathWanted:    filepath.Join(homeDir, "Library", "Application Support", "snyk", "vscode-cli"),
			Purpose:       "Default CLI Download Location for VS Code Extension",
			MayContainCLI: true,
		})
	}

	// XDG_DATA_HOME or default
	xdgDataHome := os.Getenv("XDG_DATA_HOME")
	if xdgDataHome == "" && homeDir != "" {
		xdgDataHome = filepath.Join(homeDir, ".local", "share")
	}
	if xdgDataHome != "" {
		// VS Code Extension location (default on Linux, alternative on Darwin)
		vscodeXDGLocationPurpose := "Default CLI Download Location for VS Code Extension"
		if runtime.GOOS == "darwin" {
			vscodeXDGLocationPurpose = "Alternative CLI Download Location for VS Code Extension"
		}
		dirs = append(dirs, UsedDirectory{
			PathWanted:    filepath.Join(xdgDataHome, "snyk", "vscode-cli"),
			Purpose:       vscodeXDGLocationPurpose,
			MayContainCLI: true,
		})
	}

	if homeDir != "" {
		// Eclipse Plugin location
		dirs = append(dirs, UsedDirectory{
			PathWanted:    filepath.Join(homeDir, ".snyk"),
			Purpose:       "Default CLI Download Location for Eclipse Plugin",
			MayContainCLI: true,
		})
	}

	if xdgDataHome != "" {
		// Language Server location
		dirs = append(dirs, UsedDirectory{
			PathWanted:    filepath.Join(xdgDataHome, "snyk-ls"),
			Purpose:       "Default CLI Download Location for Language Server",
			MayContainCLI: true,
		})
	}

	if homeDir != "" {
		if runtime.GOOS == "darwin" {
			// Language Server config location (macOS)
			dirs = append(dirs, UsedDirectory{
				PathWanted:    filepath.Join(homeDir, "Library", "Application Support", "snyk"),
				Purpose:       "Language Server Config Storage",
				MayContainCLI: false,
			})
		}
		if runtime.GOOS == "linux" {
			// Language Server config location (Linux)
			dirs = append(dirs, UsedDirectory{
				PathWanted:    filepath.Join(homeDir, ".config", "snyk"),
				Purpose:       "Language Server Config Storage",
				MayContainCLI: false,
			})
		}
	}

	return dirs
}

// DedupeDirectories removes duplicate directories by path and combines their purposes
func DedupeDirectories(dirs []UsedDirectory) []UsedDirectory {
	seen := make(map[string]int) // path -> index in result
	var result []UsedDirectory

	for _, dir := range dirs {
		if idx, exists := seen[dir.PathWanted]; exists {
			// Path already exists, combine purposes
			result[idx].Purpose = result[idx].Purpose + " & " + dir.Purpose
			// If any duplicate has MayContainCLI true, keep it true
			if dir.MayContainCLI {
				result[idx].MayContainCLI = true
			}
		} else {
			// New path, add to result and track index
			seen[dir.PathWanted] = len(result)
			result = append(result, dir)
		}
	}

	return result
}

// CheckDirectory checks a directory for existence, permissions, and CLI binaries
func CheckDirectory(dir UsedDirectory) DirectoryCheckResult {
	result := DirectoryCheckResult{
		PathWanted:    dir.PathWanted,
		Purpose:       dir.Purpose,
		MayContainCLI: dir.MayContainCLI,
	}

	// Check if directory exists
	info, err := os.Stat(dir.PathWanted)
	if err != nil {
		if !os.IsNotExist(err) {
			result.Error = err.Error()
			return result
		}

		// Directory doesn't exist - find the first existing parent directory
		parentPath := findParentDirectory(dir.PathWanted)
		if parentPath == "" {
			result.Error = err.Error()
			return result
		}

		// Get parent directory information
		info, err = os.Stat(parentPath)
		if err != nil {
			result.Error = err.Error()
			return result
		}

		result.PathFound = parentPath
	} else {
		// Directory exists
		result.PathFound = dir.PathWanted
	}

	// Common path: get permissions and writability
	result.Permissions = fmt.Sprintf("%04o", info.Mode().Perm())
	result.IsWritable = isWritable(result.PathFound)

	// Find CLI binaries only if the wanted directory exists and may contain a Snyk CLI binary
	if result.PathFound == result.PathWanted && dir.MayContainCLI {
		result.BinariesFound = findCLIBinaries(result.PathFound)
	}

	return result
}

// findParentDirectory finds the first existing parent directory
func findParentDirectory(path string) string {
	if path == "" {
		return ""
	}

	// Clean the path
	path = filepath.Clean(path)

	// Get parent
	parent := filepath.Dir(path)

	// If we've reached the root or same path, return empty
	if parent == path || parent == "." {
		return ""
	}

	// Check if parent exists
	_, err := os.Stat(parent)
	if err == nil {
		return parent
	}

	// Recursively check parent's parent
	return findParentDirectory(parent)
}

// isWritable checks if a directory is writable
func isWritable(path string) bool {
	// Try to create a temporary file in the directory
	testFile := filepath.Join(path, ".snyk-write-test-you-can-safely-delete-this-file")
	file, err := os.Create(testFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(testFile)
	return true
}

// findCLIBinaries searches for Snyk CLI executables in a directory
func findCLIBinaries(dir string) []BinaryInfo {
	var binaries []BinaryInfo

	entries, err := os.ReadDir(dir)
	if err != nil {
		return binaries
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fileName := entry.Name()
		// Check if it's a Snyk CLI binary
		if isProbablySnykCLI(fileName) {
			binaryPath := filepath.Join(dir, fileName)
			info, err := os.Stat(binaryPath)
			if err != nil {
				continue
			}

			binaries = append(binaries, BinaryInfo{
				Name:        fileName,
				Permissions: fmt.Sprintf("%04o", info.Mode().Perm()),
			})
		}
	}

	return binaries
}

// isProbablySnykCLI checks if a filename is possibly a Snyk CLI binary
func isProbablySnykCLI(name string) bool {
	lowerName := strings.ToLower(name)

	// Get file extension
	ext := filepath.Ext(lowerName)

	// Only allow no extension or .exe extension
	if ext != "" && ext != ".exe" {
		return false
	}

	// Check for Snyk binary patterns
	return lowerName == "snyk" ||
		strings.HasPrefix(lowerName, "snyk-") ||
		strings.HasPrefix(lowerName, "snyk.") ||
		(strings.HasPrefix(lowerName, "snyk") && strings.HasSuffix(lowerName, ".exe"))
}

// GetCurrentUser gets the current username
func GetCurrentUser() string {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Sprintf("Unable to be determined (%s)", err.Error())
	}
	return currentUser.Username
}
