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

// validatePathExistsAsFile checks if a path exists and is a file
func validatePathExistsAsFile(input, context string) error {
	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("%s does not exist or is not accessible: %w", context, err)
	}

	if info.IsDir() {
		return fmt.Errorf("%s must be a file", context)
	}
	return nil
}

// validatePathExistsAsAny checks if a path exists (file or directory)
func validatePathExistsAsAny(input, context string) error {
	if _, err := os.Stat(input); err != nil {
		return fmt.Errorf("%s does not exist or is not accessible: %w", context, err)
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

	// 2. Check for path traversal
	if err := validatePathTraversal(pathStr, "path"); err != nil {
		return err
	}

	// 3. Validate absolute path (always required)
	if err := validateAbsolutePath(pathStr, "path"); err != nil {
		return err
	}

	// 4. Validate path exists if required
	if options.RequireExists {
		if err := validatePathExistence(pathStr, options.PathType); err != nil {
			return err
		}
	}

	return nil
}

// validatePathExistence validates that a path exists and matches the expected type
func validatePathExistence(pathStr string, pathType PathType) error {
	switch pathType {
	case PathTypeDirectory:
		return validatePathExistsAsDirectory(pathStr, "path")
	case PathTypeFile:
		return validatePathExistsAsFile(pathStr, "path")
	case PathTypeAny:
		return validatePathExistsAsAny(pathStr, "path")
	default:
		return errors.New("invalid path type")
	}
}

// PathValidationOptions defines validation requirements for paths
type PathValidationOptions struct {
	AllowEmpty    bool
	RequireExists bool
	PathType      PathType
}

// PathType defines what type of filesystem object is expected
type PathType int

const (
	PathTypeAny PathType = iota
	PathTypeFile
	PathTypeDirectory
)

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

	// Use ValidatePath for comprehensive validation
	options := PathValidationOptions{
		AllowEmpty:    true,
		RequireExists: false, // Don't check existence for key generation
		PathType:      PathTypeAny,
	}

	// Check for dangerous characters, path traversal, and absolute paths
	if err := ValidatePath(p, options); err != nil {
		return ""
	}

	// Normalize the path using filepath.Clean()
	s = filepath.Clean(s)

	// Add trailing slash if missing
	if s != "" && s != "/" && !strings.HasSuffix(s, "/") && !strings.HasSuffix(s, "\\") {
		// Use the same separator as the path (forward slash for Unix, backslash for Windows)
		if strings.Contains(s, "\\") {
			s = s + "\\"
		} else {
			s = s + "/"
		}
	}
	return types.FilePath(s)
}
