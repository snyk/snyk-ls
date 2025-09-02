package util

import (
	"github.com/snyk/snyk-ls/internal/types"
)

// ValidateReferenceFolderPath validates a reference folder path for security
func ValidateReferenceFolderPath(path types.FilePath) error {
	options := PathValidationOptions{
		AllowEmpty:      true,
		RequireAbsolute: true,
		RequireExists:   true,
		PathType:        PathTypeDirectory,
	}
	return ValidatePath(path, options)
}

// ValidateFolderPath validates a folder path for security
func ValidateFolderPath(path types.FilePath) error {
	options := PathValidationOptions{
		AllowEmpty:      false,
		RequireAbsolute: true,
		RequireExists:   true,
		PathType:        PathTypeDirectory,
	}
	return ValidatePath(path, options)
}
