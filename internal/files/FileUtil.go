package files

import (
	"os"
	"strings"
)

type FileUtil struct{}

func New() *FileUtil {
	return &FileUtil{}
}

// GetLineOfCode returns the line of code from file (1-based)
func (f *FileUtil) GetLineOfCode(filePath string, line int) (string, error) {
	lines, err := f.readFile(filePath)
	if len(lines) >= line {
		return lines[line-1], nil
	}
	return "", err
}

func (f *FileUtil) readFile(filePath string) (lines []string, err error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(bytes), "\n"), nil
}
