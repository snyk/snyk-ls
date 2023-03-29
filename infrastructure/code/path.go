package code

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

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
	return filepath.Join(baseDir, relativePath)
}

func EncodePath(relativePath string) string {
	segments := strings.Split(filepath.ToSlash(relativePath), "/")
	encodedPath := ""
	for _, segment := range segments {
		encodedSegment := url.PathEscape(segment)
		encodedPath = path.Join(encodedPath, encodedSegment)
	}

	return encodedPath
}

func DecodePath(encodedRelativePath string) (string, error) {
	return url.PathUnescape(encodedRelativePath)
}
