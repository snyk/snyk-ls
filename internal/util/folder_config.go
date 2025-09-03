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
