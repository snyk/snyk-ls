package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-ls/internal/types"
)

// Common dangerous characters that could be used for injection attacks
var dangerousChars = []string{";", "&", "|", "`", "$", "\"", "'", "\n", "\r", "\t"}

// validateDangerousCharacters checks for dangerous characters in a string
func validateDangerousCharacters(input, context string) error {
	for _, char := range dangerousChars {
		if strings.Contains(input, char) {
			return fmt.Errorf("dangerous character detected in %s: %s", context, char)
		}
	}
	return nil
}

// validatePathTraversal checks for path traversal attempts
func validatePathTraversal(input, context string) error {
	// Check for explicit path traversal patterns
	if strings.Contains(input, "..") {
		return fmt.Errorf("path traversal detected in %s", context)
	}

	// Check for URL-encoded traversal patterns
	encodedPatterns := []string{"%2e%2e", "%2E%2E"}
	for _, pattern := range encodedPatterns {
		if strings.Contains(input, pattern) {
			return fmt.Errorf("encoded path traversal detected in %s", context)
		}
	}

	return nil
}

// validateAbsolutePath checks if a path is absolute
func validateAbsolutePath(input, context string) error {
	if !filepath.IsAbs(input) {
		return fmt.Errorf("%s must be absolute", context)
	}
	return nil
}

// validatePathExistsAsDirectory checks if a path exists and is a directory
func validatePathExistsAsDirectory(input, context string) error {
	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("%s does not exist or is not accessible: %w", context, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%s must be a directory", context)
	}
	return nil
}

// ValidatePath validates any path for security with customizable requirements
func ValidatePath(path types.FilePath, options PathValidationOptions) error {
	pathStr := strings.TrimSpace(string(path))
	if pathStr == "" {
		if options.AllowEmpty {
			return nil
		}
		return errors.New("path cannot be empty")
	}

	// 1. Check for dangerous characters
	if err := validateDangerousCharacters(pathStr, "path"); err != nil {
		return err
	}

	// 2. Validate absolute path (always required)
	if err := validateAbsolutePath(pathStr, "path"); err != nil {
		return err
	}

	// 3. Validate path exists if required
	if options.RequireExists {
		if err := validatePathExistsAsDirectory(pathStr, "path"); err != nil {
			return err
		}
	}

	return nil
}

// PathValidationOptions defines validation requirements for paths
type PathValidationOptions struct {
	AllowEmpty    bool
	RequireExists bool
}

// GenerateFolderConfigKey creates a normalized key for folder config storage
func GenerateFolderConfigKey(p types.FilePath) types.FilePath {
	// Empty paths can occur during data migration from old storage formats
	if p == "" {
		return ""
	}

	s := strings.TrimSpace(string(p))
	if s == "" {
		return ""
	}

	// Basic validation for folder config keys - only check for dangerous characters and path traversal
	// Don't enforce absolute path requirements since these are just storage keys
	if err := validateDangerousCharacters(s, "path"); err != nil {
		return ""
	}

	if err := validatePathTraversal(s, "path"); err != nil {
		return ""
	}

	// Normalize the path using filepath.Clean()
	s = filepath.Clean(s)

	return types.FilePath(s)
}

func ValidatePathLenient(path types.FilePath) error {
	options := PathValidationOptions{
		AllowEmpty:    true,
		RequireExists: false,
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	return nil
}

func ValidatePathStrict(path types.FilePath) error {
	options := PathValidationOptions{
		AllowEmpty:    false,
		RequireExists: true,
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	return nil
}

// ValidatePathForStorage validates a path for storage purposes without requiring the path to exist.
// This function is used when storing paths where the path may not exist yet
// (e.g., user-configured paths for future use, paths during data migration, or storage keys).
// It performs security validation (dangerous characters, path traversal) but allows empty paths
// and doesn't check if the path actually exists on the filesystem.
func ValidatePathForStorage(path types.FilePath) error {
	options := PathValidationOptions{
		AllowEmpty:    true,
		RequireExists: false, // Don't require the path to exist
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	return nil
}
