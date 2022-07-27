package files

import (
	"os"
	"strings"

	"github.com/pkg/errors"

	errorreporting "github.com/snyk/snyk-ls/domain/observability/error_reporting"
)

type FileUtil struct {
	errorReporter errorreporting.ErrorReporter
}

func New(errorReporter errorreporting.ErrorReporter) *FileUtil {
	return &FileUtil{errorReporter: errorReporter}
}

// GetLineOfCode returns the line of code from file (1-based)
func (f *FileUtil) GetLineOfCode(filePath string, line int) string {
	lines := f.readFile(filePath)
	if len(lines) >= line {
		return lines[line-1]
	}
	return ""
}

func (f *FileUtil) readFile(filePath string) (lines []string) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		f.errorReporter.CaptureError(errors.Wrap(err, "Couldn't read file "+filePath))
	}
	return strings.Split(string(bytes), "\n")
}
