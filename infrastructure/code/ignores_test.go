package code

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_LoadIgnorePatterns_DotSnykFileIsParsed(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	testData := `
exclude:
  code:
    - path/to/code/ignore1
    - path/to/code/ignore2
  global:
    - path/to/global/ignore1
    - path/to/global/ignore2
`
	expectedIgnoreRules := parseIgnoreRuleToGlobs("path/to/code/ignore1", tmpDir)
	expectedIgnoreRules = append(expectedIgnoreRules, parseIgnoreRuleToGlobs("path/to/code/ignore2", tmpDir)...)
	expectedIgnoreRules = append(expectedIgnoreRules, parseIgnoreRuleToGlobs("path/to/global/ignore1", tmpDir)...)
	expectedIgnoreRules = append(expectedIgnoreRules, parseIgnoreRuleToGlobs("path/to/global/ignore2", tmpDir)...)

	err := os.WriteFile(filepath.Join(tmpDir, ".snyk"), []byte(testData), 0644)
	assert.Nil(t, err)
	_, sc := setupTestScanner()

	_, err = sc.loadIgnorePatternsAndCountFiles(tmpDir)
	assert.Nil(t, err)

	for _, rule := range expectedIgnoreRules {
		assert.Contains(t, sc.ignorePatterns, rule)
	}
}

func Test_IgnoresWithNegationInSnykCode(t *testing.T) {
	dir := t.TempDir()
	repobase := filepath.Join(dir, "temp", "repobase")
	err := os.MkdirAll(repobase, 0755)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(repobase, ".gitignore"), []byte("!temp"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(repobase, "file1.java"), []byte("any data we would like"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	codeClientMock, scanner := setupTestScanner()

	_, _ = scanner.Scan(context.Background(), "", repobase)

	calls := codeClientMock.GetAllCalls("extendBundleWithSource")
	assert.Len(t, calls, 1)
	assert.Contains(t, scanner.ignorePatterns, "!"+filepath.ToSlash(repobase+"/**/temp"))
}

func Test_IgnoresInSnykCode(t *testing.T) {
	dir := t.TempDir()
	repoBase := filepath.Join(dir, "temp", "repoBase")
	err := os.MkdirAll(repoBase, 0755)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(repoBase, ".gitignore"), []byte("temp"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(repoBase, "file1.java"), []byte("any data we would like"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	codeClientMock, scanner := setupTestScanner()

	_, _ = scanner.Scan(context.Background(), "", repoBase)

	calls := codeClientMock.GetAllCalls("extendBundleWithSource")
	assert.Len(t, calls, 1)
}

func Test_LoadIgnorePatternsWithoutIgnoreFilePresent(t *testing.T) {
	tempDir := t.TempDir()
	_, sc := setupTestScanner()

	_, err := sc.loadIgnorePatternsAndCountFiles(tempDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace")
	}

	assert.Equal(t, getDefaultIgnorePatterns(), sc.ignorePatterns)
}

func Test_LoadIgnorePatternsAndCountFiles_RelativePathIgnores(t *testing.T) {
	testutil.UnitTest(t)
	tempDir := writeTestGitIgnore("", t)
	subDir := filepath.Join(tempDir, "evilfolder")
	_ = os.Mkdir(subDir, 0755)
	writeGitIgnoreIntoDir("*", t, subDir)
	expectedSubDirPattern := filepath.ToSlash(filepath.Join(subDir, "**/*"))

	sc := Scanner{}
	_, err := sc.loadIgnorePatternsAndCountFiles(tempDir)

	assert.NoError(t, err)
	assert.Contains(t, sc.ignorePatterns, expectedSubDirPattern)
	assert.Len(t, sc.ignorePatterns, len(getDefaultIgnorePatterns())+2)
}
