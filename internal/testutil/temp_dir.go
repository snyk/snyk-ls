package testutil

import (
	"os"
	"testing"
)

func CreateTempFile(tempDir string, t *testing.T) *os.File {
	file, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Fatal(t, "Couldn't create temp file")
	}

	t.Cleanup(func() {
		file.Close()
		_ = os.Remove(file.Name())
	})
	return file
}
