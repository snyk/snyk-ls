package diagnostics

import (
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
)

func Test_ignored_ignoredGlob(t *testing.T) {
	ignoredPath := "test.xml"

	err := os.WriteFile(ignoredPath, []byte("test"), 0600)
	defer os.RemoveAll(ignoredPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create file " + ignoredPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}

	assert.True(t, ignored(patterns, ignoredPath))
}

func Test_ignored_notIgnored(t *testing.T) {
	notIgnoredPath := "not-ignored.txt"
	err := os.WriteFile(notIgnoredPath, []byte("test"), 0600)
	defer os.RemoveAll(notIgnoredPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create file " + notIgnoredPath)
	}
	patterns := []string{"**/ignored.txt", "*.xml"}

	assert.False(t, ignored(patterns, notIgnoredPath))
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
	assert.True(t, ignored(patterns, ignoredDoubleAsteriskPath))
}

func Test_LoadIgnorePatternsWithIgnoreFilePresent(t *testing.T) {
	expectedPatterns, tempDir, _, _ := setupIgnoreWorkspace()
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
	_, workspace, ignoredFilePath, notIgnoredFilePath := setupIgnoreWorkspace()
	defer os.RemoveAll(workspace)

	err := registerAllFilesFromWorkspace(sglsp.DocumentURI("file://" + workspace))
	if err != nil {
		log.Fatal().Err(err).Msg("Error while registering " + workspace)
	}
	assert.Equal(t, 2, len(registeredDocuments)) //.gitignore & notIgnoredFilePath
	assert.NotEqual(t, sglsp.TextDocumentItem{}, registeredDocuments[sglsp.DocumentURI("file://"+notIgnoredFilePath)])
	assert.Equal(t, sglsp.TextDocumentItem{}, registeredDocuments[sglsp.DocumentURI(ignoredFilePath)])
}

func writeTestGitIgnore(ignorePatterns string) string {
	temp, err := os.MkdirTemp(os.TempDir(), "loadIgnorePatterns")
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create temp dir")
	}
	err = os.WriteFile(temp+string(os.PathSeparator)+".gitignore", []byte(ignorePatterns), 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't write .gitignore")
	}
	return temp
}

func setupIgnoreWorkspace() (string, string, string, string) {
	expectedPatterns := "*.xml\n**/*.txt\nbin"
	tempDir := writeTestGitIgnore(expectedPatterns)

	ignoredFilePath := tempDir + string(os.PathSeparator) + "ignored.xml"
	err := os.WriteFile(ignoredFilePath, []byte("test"), 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't write ignored file ignored.xml")
	}
	notIgnoredFilePath := tempDir + string(os.PathSeparator) + "not-ignored.java"
	err = os.WriteFile(notIgnoredFilePath, []byte("test"), 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't write ignored file not-ignored.java")
	}
	return expectedPatterns, tempDir, ignoredFilePath, notIgnoredFilePath
}
