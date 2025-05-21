//go:build darwin

/*
 * © 2025 Snyk Limited
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
	"syscall"
)

// isCaseInsensitive determines if a macOS filesystem at the given path is case-insensitive
// returns true if case-insensitive, false if case-sensitive
func isCaseInsensitive(dirPath string) bool {
	// Create two temporary files with different case
	tempFile1 := filepath.Join(dirPath, ".snyk-case-test")
	tempFile2 := filepath.Join(dirPath, ".SNYK-CASE-TEST")

	// Clean up when done
	defer func(name string) {
		_ = os.Remove(name)
	}(tempFile1)
	defer func(name string) {
		_ = os.Remove(name)
	}(tempFile2)

	// Create the first file
	f, err := osCreate(tempFile1)
	if err != nil {
		// If we can't create a file, default to the safe option on macOS (case-sensitive)
		return false
	}
	_ = f.Close()

	// Try to create the second file with different case
	_, err = osCreate(tempFile2)
	if err != nil {
		// If we can't create the second file, filesystem is case-insensitive
		return true
	}

	// Check if the files have the same inode on macOS, which means they're the same file
	// This is a reliable way to check case sensitivity on macOS
	info1, err1 := os.Stat(tempFile1)
	info2, err2 := os.Stat(tempFile2)

	if err1 == nil && err2 == nil {
		stat1, ok1 := info1.Sys().(*syscall.Stat_t)
		stat2, ok2 := info2.Sys().(*syscall.Stat_t)

		// Only compare inodes if both type assertions succeeded
		if ok1 && ok2 {
			// If they have the same inode, filesystem is case-insensitive
			return stat1.Ino == stat2.Ino
		}
	}

	// Default to true for macOS (most macOS partitions are case-insensitive)
	return true
}
