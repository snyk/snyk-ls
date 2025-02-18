package code

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/internal/types"
)

func ToRelativeUnixPath(baseDir types.FilePath, absoluteFilePath types.FilePath) (types.FilePath, error) {
	relativePath, err := filepath.Rel(string(baseDir), string(absoluteFilePath))
	if err != nil {
		relativePath = string(absoluteFilePath)
		if baseDir != "" {
			errMsg := fmt.Sprint("could not get relative path for file: ", absoluteFilePath, " and root path: ", baseDir)
			return "", errors.Wrap(err, errMsg)
		}
	}

	relativePath = filepath.ToSlash(relativePath) // treat all paths as unix paths
	return types.FilePath(relativePath), nil
}

func ToAbsolutePath(baseDir types.FilePath, relativePath types.FilePath) string {
	return filepath.Join(string(baseDir), string(relativePath))
}

func EncodePath(relativePath types.FilePath) types.FilePath {
	segments := strings.Split(filepath.ToSlash(string(relativePath)), "/")
	encodedPath := ""
	for _, segment := range segments {
		encodedSegment := url.PathEscape(segment)
		encodedPath = path.Join(encodedPath, encodedSegment)
	}

	return types.FilePath(encodedPath)
}

func DecodePath(encodedRelativePath string) (string, error) {
	return url.PathUnescape(encodedRelativePath)
}
