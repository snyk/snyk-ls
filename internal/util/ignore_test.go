package util

import (
	"os"
	"testing"

	ignore "github.com/sabhiram/go-gitignore"
	"github.com/stretchr/testify/assert"
)

func Test_ignored_ignoredGlob(t *testing.T) {
	ignoredPath := "test.xml"

	err := os.WriteFile(ignoredPath, []byte("test"), 0600)
	defer os.RemoveAll(ignoredPath)
	if err != nil {
		t.Fatal(t, err, "Couldn't create file "+ignoredPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}

	assert.True(t, Ignored(ignore.CompileIgnoreLines(patterns...), ignoredPath))
}

func Test_ignored_notIgnored(t *testing.T) {
	notIgnoredPath := "not-ignored.txt"
	err := os.WriteFile(notIgnoredPath, []byte("test"), 0600)
	defer os.RemoveAll(notIgnoredPath)
	if err != nil {
		t.Fatal(t, err, "Couldn't create file "+notIgnoredPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}

	assert.False(t, Ignored(ignore.CompileIgnoreLines(patterns...), notIgnoredPath))
}

func Test_ignored_doubleAsterisk(t *testing.T) {
	ignoredDoubleAsteriskPath := "test-ignore/ignored.txt"
	testIgnoreDir := "test-ignore"
	err := os.Mkdir(testIgnoreDir, 0755)
	defer os.RemoveAll(testIgnoreDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't create testIgnoreDir"+testIgnoreDir)
	}
	err = os.WriteFile(ignoredDoubleAsteriskPath, []byte("test"), 0600)
	defer os.RemoveAll(ignoredDoubleAsteriskPath)
	if err != nil {
		t.Fatal(t, err, "Couldn't create file "+ignoredDoubleAsteriskPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}
	assert.True(t, Ignored(ignore.CompileIgnoreLines(patterns...), ignoredDoubleAsteriskPath))
}
