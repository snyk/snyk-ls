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
	folder := NewFolder("testPath/a.txt", "testFolder")
	key := "bundleHash"
	value := "testHash"

	folder.AddProductAttribute(SnykCode, key, value)

	assert.Equal(t, value, folder.GetProductAttribute(SnykCode, key))
}

func Test_LoadIgnorePatternsWithIgnoreFilePresent(t *testing.T) {
	expectedPatterns, tempDir, _, _, _ := setupIgnoreWorkspace()
	defer os.RemoveAll(tempDir)
	folder := NewFolder(tempDir, "Test_LoadIgnorePatternsWithIgnoreFilePresent")

	actualPatterns, err := folder.loadIgnorePatterns()
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace "+tempDir)
	}

	assert.Equal(t, strings.Split(expectedPatterns, "\n"), actualPatterns)
	assert.Equal(t, strings.Split(expectedPatterns, "\n"), folder.ignorePatterns)
}

func Test_LoadIgnorePatternsWithoutIgnoreFilePresent(t *testing.T) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "loadIgnoreTest")
	defer os.RemoveAll(tempDir)
	folder := NewFolder(tempDir, "Test_LoadIgnorePatternsWithoutIgnoreFilePresent")

	actualPatterns, err := folder.loadIgnorePatterns()
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace")
	}

	assert.Equal(t, []string{""}, actualPatterns)
	assert.Equal(t, []string{""}, folder.ignorePatterns)
}

func Test_GetWorkspaceFolderFiles(t *testing.T) {
	_, path, ignoredFilePath, notIgnoredFilePath, _ := setupIgnoreWorkspace()
	defer os.RemoveAll(path)
	folder := NewFolder(path, "Test_GetWorkspaceFolderFiles")

	files, err := folder.Files()
	if err != nil {
		t.Fatal(t, err, "Error getting workspace folder files: "+path)
	}

	assert.Len(t, files, 2)
	assert.Contains(t, files, notIgnoredFilePath)
	assert.NotContains(t, files, ignoredFilePath)
}

func Test_GetWorkspaceFiles_SkipIgnoredDirs(t *testing.T) {
	_, path, _, _, ignoredFileInDir := setupIgnoreWorkspace()
	defer os.RemoveAll(path)
	folder := NewFolder(path, "Test_GetWorkspaceFolderFiles")

	walkedFiles, err := folder.Files()
	if err != nil {
		t.Fatal(t, err, "Error while registering "+path)
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

func Test_LoadIgnorePatternsWithIgnoreFilePresent(t *testing.T) {
	expectedPatterns, tempDir, _, _, _ := setupIgnoreWorkspace()
	defer os.RemoveAll(tempDir)
	folder := NewFolder(tempDir, "Test_LoadIgnorePatternsWithIgnoreFilePresent")

	actualPatterns, err := folder.loadIgnorePatterns()
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace "+tempDir)
	}

	assert.Equal(t, strings.Split(expectedPatterns, "\n"), actualPatterns)
	assert.Equal(t, strings.Split(expectedPatterns, "\n"), folder.ignorePatterns)
}

func Test_LoadIgnorePatternsWithoutIgnoreFilePresent(t *testing.T) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "loadIgnoreTest")
	defer os.RemoveAll(tempDir)
	folder := NewFolder(tempDir, "Test_LoadIgnorePatternsWithoutIgnoreFilePresent")

	actualPatterns, err := folder.loadIgnorePatterns()
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace")
	}

	assert.Equal(t, []string{""}, actualPatterns)
	assert.Equal(t, []string{""}, folder.ignorePatterns)
}

func Test_GetWorkspaceFolderFiles(t *testing.T) {
	_, path, ignoredFilePath, notIgnoredFilePath, _ := setupIgnoreWorkspace()
	defer os.RemoveAll(path)
	folder := NewFolder(path, "Test_GetWorkspaceFolderFiles")

	files, err := folder.Files()
	if err != nil {
		t.Fatal(t, err, "Error getting workspace folder files: "+path)
	}

	assert.Len(t, files, 2)
	assert.Contains(t, files, notIgnoredFilePath)
	assert.NotContains(t, files, ignoredFilePath)
}

func Test_GetWorkspaceFiles_SkipIgnoredDirs(t *testing.T) {
	_, path, _, _, ignoredFileInDir := setupIgnoreWorkspace()
	defer os.RemoveAll(path)
	folder := NewFolder(path, "Test_GetWorkspaceFolderFiles")

	walkedFiles, err := folder.Files()
	if err != nil {
		t.Fatal(t, err, "Error while registering "+path)
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
