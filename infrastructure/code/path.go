package code

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"
)

// Send for analysis: absolutePath -> relativePath -> encodeUri
// Produce snyk.Issue results: decodeUri -> relativePath -> absolutePath

func ToRelativeUnixPath(baseDir string, absoluteFilePath string) (string, error) {
	relativePath, err := filepath.Rel(baseDir, absoluteFilePath)
	if err != nil {
		relativePath = absoluteFilePath
		if baseDir != "" {
			errMsg := fmt.Sprint("could not get relative path for file: ", absoluteFilePath, " and root path: ", baseDir)
			return "", errors.Wrap(err, errMsg)
		}
	}

	relativePath = filepath.ToSlash(relativePath) // treat all paths as unix paths
	return relativePath, nil
}

func ToAbsolutePath(baseDir string, relativePath string) string {
	absolutePath := filepath.Join(baseDir, relativePath)

	return absolutePath
}

func EncodePath(relativePath string) string {
	return ""
}

func DecodePath(encodedRelativePath string) string {
	return ""
}
