/*
 * © 2024-2026 Snyk Limited
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

package types

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FilePath represents a file system path
type FilePath string

// ExistenceType defines what type of existence validation to perform
type ExistenceType int

const (
	NoCheck ExistenceType = iota
	ExistAsFileOrDirectory
	ExistAsDirectory
	ExistAsFile
)

// PathValidationOptions defines validation requirements for paths
type PathValidationOptions struct {
	AllowEmpty bool
	Existence  ExistenceType
}

// ValidatePath validates any path for security with customizable requirements
func ValidatePath(path FilePath, options PathValidationOptions) error {
	pathStr := strings.TrimSpace(string(path))
	if pathStr == "" {
		if options.AllowEmpty {
			return nil
		}
		return fmt.Errorf("path cannot be empty, got: '%s'", string(path))
	}

	// Validate path existence based on requirements
	if err := validatePathExistence(pathStr, options.Existence); err != nil {
		return err
	}

	return nil
}

// ValidatePathLenient validates a path with lenient requirements (allows empty, no existence check)
func ValidatePathLenient(path FilePath) error {
	options := PathValidationOptions{
		AllowEmpty: true,
		Existence:  NoCheck,
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("path validation failed for '%s': %w", string(path), err)
	}
	return nil
}

// ValidatePathStrict validates a path with strict requirements (no empty, must be directory)
func ValidatePathStrict(path FilePath) error {
	options := PathValidationOptions{
		AllowEmpty: false,
		Existence:  ExistAsDirectory,
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("path validation failed for '%s': %w", string(path), err)
	}
	return nil
}

// ValidatePathForStorage validates a path for storage purposes without requiring the path to exist.
// This function is used when storing paths where the path may not exist yet
// (e.g., user-configured paths for future use, paths during data migration, or storage keys).
// It allows empty paths and doesn't check if the path actually exists on the filesystem.
func ValidatePathForStorage(path FilePath) error {
	options := PathValidationOptions{
		AllowEmpty: true,
		Existence:  NoCheck, // No existence validation needed
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("path validation failed for '%s': %w", string(path), err)
	}
	return nil
}

// PathKey creates a normalized key for path storage
func PathKey(p FilePath) FilePath {
	// Empty paths can occur during data migration from old storage formats
	if p == "" {
		return ""
	}

	s := strings.TrimSpace(string(p))
	if s == "" {
		return ""
	}

	// Normalize the path using filepath.Clean()
	s = filepath.Clean(s)

	return FilePath(s)
}

// validatePathExistence checks path existence based on the specified type
func validatePathExistence(input string, existence ExistenceType) error {
	switch existence {
	case NoCheck:
		// No validation needed - path can exist or not
		return nil
	case ExistAsFileOrDirectory:
		return validatePathExists(input)
	case ExistAsDirectory:
		return validatePathExistsAsDirectory(input)
	case ExistAsFile:
		return validatePathExistsAsFile(input)
	default:
		return fmt.Errorf("unknown existence type: %v", existence)
	}
}

// validatePathExists checks if a path exists (file or directory)
func validatePathExists(input string) error {
	_, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("path does not exist or is not accessible: '%s': %w", input, err)
	}
	return nil
}

// validatePathExistsAsDirectory checks if a path exists and is a directory
func validatePathExistsAsDirectory(input string) error {
	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("path does not exist or is not accessible: '%s': %w", input, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path exists but is not a directory: '%s'", input)
	}
	return nil
}

// validatePathExistsAsFile checks if a path exists and is a file
func validatePathExistsAsFile(input string) error {
	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("path does not exist or is not accessible: '%s': %w", input, err)
	}
	if info.IsDir() {
		return fmt.Errorf("path exists but is a directory, not a file: '%s'", input)
	}
	return nil
}
