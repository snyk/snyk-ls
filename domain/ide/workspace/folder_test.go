package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestAddBundleHashToWorkspaceFolder(t *testing.T) {
	testutil.UnitTest(t)
	workspace := &Workspace{}
	f := NewFolder(".", "Test", workspace)
	workspace.AddFolder(f)
	key := "bundleHash"
	value := "testHash"

	f.AddProductAttribute(SnykCode, key, value)

	assert.Equal(t, value, f.GetProductAttribute(SnykCode, key))
}

func Test_LoadIgnorePatternsWithIgnoreFilePresent(t *testing.T) {
	expectedPatterns, tempDir, _, _, _ := setupIgnoreWorkspace()
	defer os.RemoveAll(tempDir)
	workspace := &Workspace{}
	f := NewFolder(tempDir, "Test", workspace)
	workspace.AddFolder(f)

	actualPatterns, err := f.loadIgnorePatterns()
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace "+tempDir)
	}

	assert.Equal(t, strings.Split(expectedPatterns, "\n"), actualPatterns)
	assert.Equal(t, strings.Split(expectedPatterns, "\n"), f.ignorePatterns)
}

func Test_LoadIgnorePatternsWithoutIgnoreFilePresent(t *testing.T) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "loadIgnoreTest")
	if err != nil {
		t.Fatal("can't create temp dir")
	}
	defer os.RemoveAll(tempDir)
	workspace := &Workspace{}
	f := NewFolder(tempDir, "Test", workspace)
	workspace.AddFolder(f)

	actualPatterns, err := f.loadIgnorePatterns()
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace")
	}

	assert.Equal(t, []string{""}, actualPatterns)
	assert.Equal(t, []string{""}, f.ignorePatterns)
}

func Test_GetWorkspaceFolderFiles(t *testing.T) {
	_, tempDir, ignoredFilePath, notIgnoredFilePath, _ := setupIgnoreWorkspace()
	defer os.RemoveAll(tempDir)
	workspace := &Workspace{}
	f := NewFolder(tempDir, "Test", workspace)
	workspace.AddFolder(f)

	files, err := f.Files()
	if err != nil {
		t.Fatal(t, err, "Error getting workspace folder files: "+tempDir)
	}

	assert.Len(t, files, 2)
	assert.Contains(t, files, notIgnoredFilePath)
	assert.NotContains(t, files, ignoredFilePath)
}

func Test_GetWorkspaceFiles_SkipIgnoredDirs(t *testing.T) {
	_, tempDir, _, _, ignoredFileInDir := setupIgnoreWorkspace()
	defer os.RemoveAll(tempDir)
	workspace := &Workspace{}
	f := NewFolder(tempDir, "Test", workspace)
	workspace.AddFolder(f)

	walkedFiles, err := f.Files()
	if err != nil {
		t.Fatal(t, err, "Error while registering "+tempDir)
	}
	assert.NotContains(t, walkedFiles, ignoredFileInDir)
}

func writeTestGitIgnore(ignorePatterns string) (tempDir string) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "loadIgnorePatterns")
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create temp dir")
	}
	filePath := filepath.Join(tempDir, ".gitignore")
	err = os.WriteFile(filePath, []byte(ignorePatterns), 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't write .gitignore")
	}
	return tempDir
}

func setupIgnoreWorkspace() (expectedPatterns string, tempDir string, ignoredFilePath string, notIgnoredFilePath string, ignoredFileInDir string) {
	expectedPatterns = "*.xml\n**/*.txt\nbin"
	tempDir = writeTestGitIgnore(expectedPatterns)

	ignoredFilePath = filepath.Join(tempDir, "ignored.xml")
	err := os.WriteFile(ignoredFilePath, []byte("test"), 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't write ignored file ignored.xml")
	}
	notIgnoredFilePath = filepath.Join(tempDir, "not-ignored.java")
	err = os.WriteFile(notIgnoredFilePath, []byte("test"), 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't write ignored file not-ignored.java")
	}
	ignoredDir := filepath.Join(tempDir, "bin")
	err = os.Mkdir(ignoredDir, 0755)
	if err != nil {
		log.Fatal().Err(err).Msgf("Couldn't write ignoreDirectory %s", ignoredDir)
	}
	ignoredFileInDir = filepath.Join(ignoredDir, "shouldNotBeWalked.java")
	err = os.WriteFile(ignoredFileInDir, []byte("public bla"), 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't write ignored file not-ignored.java")
	}
	return expectedPatterns, tempDir, ignoredFilePath, notIgnoredFilePath, ignoredFileInDir
}
