package files

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLineOfCode(t *testing.T) {
	t.Run("correct line", func(t *testing.T) {
		fileName := setupCodeFile(t)
		f := New()

		actual, err := f.GetLineOfCode(fileName, 3)

		assert.NoError(t, err)
		assert.Equal(t, "Line3", actual)
	})
	t.Run("incorrect line", func(t *testing.T) {
		fileName := setupCodeFile(t)
		f := New()

		actual, err := f.GetLineOfCode(fileName, 5)
		assert.NoError(t, err)
		assert.Equal(t, "", actual)
	})

}

func setupCodeFile(t *testing.T) string {
	dir := t.TempDir()
	fileName := filepath.Join(dir, "testFile")
	err := os.WriteFile(fileName, []byte("Line1\nLine2\nLine3\nLine4"), 0660)
	if err != nil {
		t.Fatal(t, err, "Couldn't create test file")
	}
	return fileName
}
