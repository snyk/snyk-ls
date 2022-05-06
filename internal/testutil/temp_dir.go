package testutil

import (
	"io/ioutil"
	"os"
	"testing"
)

func CreateTempFile(tempDir string, t *testing.T) *os.File {
	file, err := ioutil.TempFile(tempDir, "")
	if err != nil {
		t.Fatal(t, "Couldn't create temp file")
	}

	t.Cleanup(func() {
		_ = os.Remove(file.Name())
	})
	return file
}
