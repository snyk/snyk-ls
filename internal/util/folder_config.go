package util

import (
	"fmt"

	"github.com/snyk/snyk-ls/internal/types"
)

func ValidateReferenceFolderPath(path types.FilePath) error {
	options := PathValidationOptions{
		AllowEmpty:    true,
		RequireExists: true,
		PathType:      PathTypeDirectory,
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
		PathType:      PathTypeDirectory,
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("folder path validation failed: %w", err)
	}
	return nil
}

func ValidateUserSettingsPath(path string) error {
	// Allow empty paths since users might not set a custom path
	if path == "" {
		return nil
	}

	options := PathValidationOptions{
		AllowEmpty:    true,
		RequireExists: true,
		PathType:      PathTypeDirectory,
	}
	if err := ValidatePath(types.FilePath(path), options); err != nil {
		return fmt.Errorf("user settings path validation failed: %w", err)
	}
	return nil
}

func ValidateFolderPathLenient(path types.FilePath) error {
	// Allow empty paths
	if path == "" {
		return nil
	}

	options := PathValidationOptions{
		AllowEmpty:    true,
		RequireExists: false, // Don't require the path to exist
		PathType:      PathTypeDirectory,
	}
	if err := ValidatePath(path, options); err != nil {
		return fmt.Errorf("folder path validation failed: %w", err)
	}
	return nil
}
