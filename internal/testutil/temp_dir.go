package testutil

import (
	"io/ioutil"
	"testing"
)

func CreateTempDir(t *testing.T) string {
	t.Helper()
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return tempDir
}
