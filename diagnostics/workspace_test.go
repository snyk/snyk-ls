package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/util"
)

func Test_ignored_ignoredGlob(t *testing.T) {
	ignoredPath := "test.xml"

	err := os.WriteFile(ignoredPath, []byte("test"), 0600)
	defer os.RemoveAll(ignoredPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create file " + ignoredPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}

	assert.True(t, ignored(ignore.CompileIgnoreLines(patterns...), ignoredPath))
}

func Test_ignored_notIgnored(t *testing.T) {
	notIgnoredPath := "not-ignored.txt"
	err := os.WriteFile(notIgnoredPath, []byte("test"), 0600)
	defer os.RemoveAll(notIgnoredPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create file " + notIgnoredPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}

	assert.False(t, ignored(ignore.CompileIgnoreLines(patterns...), notIgnoredPath))
}

func Test_ignored_doubleAsterisk(t *testing.T) {
	ignoredDoubleAsteriskPath := "test-ignore/ignored.txt"
	testIgnoreDir := "test-ignore"
	err := os.Mkdir(testIgnoreDir, 0700)
	defer os.RemoveAll(testIgnoreDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create testIgnoreDir" + testIgnoreDir)
	}
	err = os.WriteFile(ignoredDoubleAsteriskPath, []byte("test"), 0600)
	defer os.RemoveAll(ignoredDoubleAsteriskPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create file " + ignoredDoubleAsteriskPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}
	assert.True(t, ignored(ignore.CompileIgnoreLines(patterns...), ignoredDoubleAsteriskPath))
}

func Test_LoadIgnorePatternsWithIgnoreFilePresent(t *testing.T) {
	expectedPatterns, tempDir, _, _, _ := setupIgnoreWorkspace()
	defer os.RemoveAll(tempDir)

	actualPatterns, err := loadIgnorePatterns(tempDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't load .gitignore from workspace " + tempDir)
	}
	assert.Equal(t, strings.Split(expectedPatterns, "\n"), actualPatterns)
}

func Test_LoadIgnorePatternsWithoutIgnoreFilePresent(t *testing.T) {
	temp, err := os.MkdirTemp(os.TempDir(), "loadIgnoreTest")
	defer os.RemoveAll(temp)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't set up test directory")
	}
	var actualPatterns []string
	actualPatterns, err = loadIgnorePatterns(temp)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't load .gitignore from workspace")
	}
	assert.Equal(t, []string{""}, actualPatterns)
}

func Test_RegisterAllFilesFromWorkspace_Without_Ignored(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	_, workspace, ignoredFilePath, notIgnoredFilePath, _ := setupIgnoreWorkspace()
	defer os.RemoveAll(workspace)

	_, err := registerAllFilesFromWorkspace(util.PathToUri(workspace))
	if err != nil {
		log.Fatal().Err(err).Msg("Error while registering " + workspace)
	}
	assert.Equal(t, 2, len(registeredDocuments)) //.gitignore & notIgnoredFilePath
	assert.NotEqual(t, sglsp.TextDocumentItem{}, registeredDocuments[util.PathToUri(notIgnoredFilePath)])
	assert.Equal(t, false, registeredDocuments[sglsp.DocumentURI(ignoredFilePath)])
}

func Test_RegisterAllFilesFromWorkspace_SkipIgnoredDirs(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	_, workspace, _, _, ignoredFileInDir := setupIgnoreWorkspace()
	defer os.RemoveAll(workspace)

	walkedFiles, err := registerAllFilesFromWorkspace(util.PathToUri(workspace))
	if err != nil {
		log.Fatal().Err(err).Msg("Error while registering " + workspace)
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

	ignoredFilePath = filepath.Join(tempDir) + "ignored.xml"
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
	err = os.Mkdir(ignoredDir, 0700)
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
