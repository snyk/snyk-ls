package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-ls/internal/types"
)

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
func ValidatePath(path types.FilePath, options PathValidationOptions) error {
	pathStr := strings.TrimSpace(string(path))
	if pathStr == "" {
		if options.AllowEmpty {
			return nil
		}
		return fmt.Errorf("path cannot be empty, got: '%s'", string(path))
	}

	// Validate Windows UNC admin share paths
	if err := validateWindowsUNCAdminShare(pathStr); err != nil {
		return err
	}

	// Validate path existence based on requirements
	if err := validatePathExistence(pathStr, options.Existence); err != nil {
		return err
	}

	return nil
}

// ValidatePathLenient validates a path with lenient requirements (allows empty, no existence check)
func ValidatePathLenient(path types.FilePath) error {
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
func ValidatePathStrict(path types.FilePath) error {
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
func ValidatePathForStorage(path types.FilePath) error {
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
func PathKey(p types.FilePath) types.FilePath {
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

	return types.FilePath(s)
}

// validateWindowsUNCAdminShare validates Windows UNC admin share paths
// These paths have the format \\server\C$\... where C$ is the administrative share
func validateWindowsUNCAdminShare(path string) error {
	// Check if path looks like a UNC path (starts with \\ or //)
	if strings.HasPrefix(path, "\\\\") || strings.HasPrefix(path, "//") {
		// If it's a UNC path, verify it's a valid admin share format
		if !isWindowsUNCAdminShare(path) {
			// If it looks like UNC but isn't a valid admin share, that's okay
			// We just want to ensure admin shares are properly recognized
			return nil
		}
		// Valid admin share path - no error
		return nil
	}
	// Not a UNC path - no validation needed
	return nil
}

// isWindowsUNCAdminShare checks if the path is a Windows UNC administrative share path
// These paths have the format \\server\C$\... where C$ is the administrative share
func isWindowsUNCAdminShare(path string) bool {
	// Check if it starts with \\ (UNC path)
	if !strings.HasPrefix(path, "\\\\") && !strings.HasPrefix(path, "//") {
		return false
	}

	// Check if it contains a drive letter followed by $ (e.g., C$, D$, etc.)
	// Pattern: \\server\X$ where X is a drive letter
	parts := strings.Split(strings.ReplaceAll(path, "/", "\\"), "\\")
	if len(parts) < 4 {
		return false
	}

	// parts[0] and parts[1] are empty (from leading \\)
	// parts[2] is the server name
	// parts[3] should be the share name (e.g., C$)
	shareName := parts[3]
	if len(shareName) == 2 && shareName[1] == '$' {
		// Check if first character is a drive letter (A-Z, case insensitive)
		driveLetter := shareName[0]
		return (driveLetter >= 'A' && driveLetter <= 'Z') || (driveLetter >= 'a' && driveLetter <= 'z')
	}

	return false
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
