package util

import (
	"fmt"

	"github.com/snyk/snyk-ls/internal/types"
)

func ValidateReferenceFolderPath(path types.FilePath) error {
	options := PathValidationOptions{
		AllowEmpty:    true,
		RequireExists: false,
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("reference folder path validation failed: %w", err)
	}
	return nil
}

func ValidateFolderPath(path types.FilePath) error {
	options := PathValidationOptions{
		AllowEmpty:    false,
		RequireExists: true,
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("folder path validation failed: %w", err)
	}
	return nil
}

// ValidateFolderPathLenient validates a folder path for storage purposes without requiring the path to exist.
// This function is used when storing folder configurations where the path may not exist yet
// (e.g., user-configured paths for future use, paths during data migration, or storage keys).
// It performs security validation (dangerous characters, path traversal) but allows empty paths
// and doesn't check if the path actually exists on the filesystem.
func ValidateFolderPathLenient(path types.FilePath) error {
	// Allow empty paths
	if path == "" {
		return nil
	}

	options := PathValidationOptions{
		AllowEmpty:    true,
		RequireExists: false, // Don't require the path to exist
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("folder path validation failed: %w", err)
	}
	return nil
}
