package install

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestInstaller_Find(t *testing.T) {
	testutil.IntegTest(t)

	// prepare temp directory with OS specific dummy CLI binary
	d := &Discovery{}
	cliDir := testutil.CreateTempDir(t)
	cliFilePath := filepath.Join(cliDir, d.ExecutableName())
	f, _ := os.Create(cliFilePath)
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	_, _ = f.WriteString("dummy-cli-file")
	_ = f.Chmod(0777)

	t.Setenv("PATH", cliDir)

	i := NewInstaller()

	execPath, err := i.Find()

	assert.NoError(t, err)
	assert.NotEmpty(t, execPath)
}

func TestInstaller_Find_emptyPath(t *testing.T) {
	testutil.IntegTest(t)
	t.Skipf("removes real binaries from user directory")

	t.Setenv("PATH", "")
	i := NewInstaller()

	execPath, err := i.Find()

	assert.Error(t, err)
	assert.Empty(t, execPath)
}
