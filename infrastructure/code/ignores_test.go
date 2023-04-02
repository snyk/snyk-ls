package code

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

type ignoreFilesTestCase struct {
	// The name of the test case. Will be used as the test name in t.Run()
	name string
	// Path to the repo to be scanned
	repoPath string
	// Path to the ignore file. Files path is relative to the repoPath
	ignoreFilePath    string
	ignoreFileContent string
	// Will assert that these files are in the list of files to be uploaded. Files paths are relative to the repoPath
	expectedFiles []string
	// Will assert that these files are not in the list of files to be uploaded. Files paths are relative to the repoPath
	expectedExcludes []string
}

func Test_SnykCodeScan_CallsExtendBundle(t *testing.T) {

	cases := []ignoreFilesTestCase{
		{
			name:              "Does not ignore files when no ignored file is present",
			repoPath:          t.TempDir(),
			ignoreFilePath:    ".gitignore",
			ignoreFileContent: "temp\n",
			expectedFiles:     []string{"file1.java", "file2.java"},
			expectedExcludes:  []string{},
		},
		{
			name:              "Respects ignore rules",
			repoPath:          t.TempDir(),
			ignoreFilePath:    ".gitignore",
			ignoreFileContent: "*.java\n",
			expectedFiles:     []string{},
			expectedExcludes:  []string{"file1.java", "file2.java"},
		},
		{
			name:           "Respects .snyk ignore rules",
			repoPath:       t.TempDir(),
			ignoreFilePath: ".snyk",
			ignoreFileContent: `
exclude:
  code:
    - path/to/code/ignore1
    - path/to/code/ignore2
  global:
    - path/to/global/ignore1
    - path/to/global/ignore2
`,
			expectedFiles: []string{"path/to/code/notIgnored.java"},
			expectedExcludes: []string{
				"path/to/code/ignore1/ignoredFile.java",
				"path/to/code/ignore2/ignoredFile.java",
				"path/to/global/ignore1/ignoredFile.java",
				"path/to/global/ignore2/ignoredFile.java",
			},
		},
		{
			name:              "Respects negation rules",
			repoPath:          t.TempDir(),
			ignoreFilePath:    ".gitignore",
			ignoreFileContent: ("*.java\n") + ("!file1.java\n"),
			expectedFiles:     []string{"file1.java"},
			expectedExcludes:  []string{"file2.java"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			setupIgnoreFilesTest(t, testCase)

			codeClientMock, scanner := setupTestScanner()
			_, _ = scanner.Scan(context.Background(), testCase.repoPath, testCase.repoPath)

			assertBundleExtendedCorrectly(t, codeClientMock, testCase.expectedFiles, testCase.expectedExcludes)
		})
	}
}

func Test_SnykCodeScan_SeveralWorkDirs_IgnoreRulesAreRespectedPerWorkDir(t *testing.T) {
	// Arrange - set 2 repos with different ignore rules. Each repo will have foo.go and bar.go files.
	// In repo A, foo.go will be ignored, and in repo B, bar.go will be ignored.
	tempDir := t.TempDir()
	testCases := []ignoreFilesTestCase{{
		repoPath:          filepath.Join(tempDir, "A"),
		ignoreFilePath:    ".gitignore",
		ignoreFileContent: "bar.go\n",
		expectedFiles:     []string{"foo.go"},
		expectedExcludes:  []string{"bar.go"},
	}, {
		repoPath:          filepath.Join(tempDir, "B"),
		ignoreFilePath:    ".gitignore",
		ignoreFileContent: "foo.go\n",
		expectedFiles:     []string{"bar.go"},
		expectedExcludes:  []string{"foo.go"},
	}}
	for _, testCase := range testCases {
		setupIgnoreFilesTest(t, testCase)
	}

	codeClientMock, scanner := setupTestScanner()

	// Scanning both repos with the same scanner catches errors that happen when the ignore rules are cached incorrectly
	// between different work dirs.
	for _, testCase := range testCases {
		_, _ = scanner.Scan(context.Background(), testCase.repoPath, testCase.repoPath)
		assertBundleExtendedCorrectly(t, codeClientMock, testCase.expectedFiles, testCase.expectedExcludes)
	}
}

func setupIgnoreFilesTest(t *testing.T, testCase ignoreFilesTestCase) {
	t.Helper()
	allFiles := append(testCase.expectedFiles, testCase.expectedExcludes...)

	ignoreFileAbsPath := filepath.Join(testCase.repoPath, testCase.ignoreFilePath)
	testutil.CreateFileOrFail(t, ignoreFileAbsPath, []byte(testCase.ignoreFileContent))
	for _, fileRelPath := range allFiles {
		absPath := filepath.Join(testCase.repoPath, fileRelPath)
		testutil.CreateFileOrFail(t, absPath, []byte("some content to avoid skipping"))
	}
}

func assertBundleExtendedCorrectly(t *testing.T,
	codeClientMock *FakeSnykCodeClient,
	expectedFiles []string,
	expectedExcludes []string,
) {
	t.Helper()
	if len(expectedFiles) > 0 { // Extend bundle shouldn't be called when no files are expected to be uploaded
		assert.True(t, codeClientMock.HasExtendedBundle)
	}
	for _, expectedFile := range expectedFiles {
		assert.Contains(t, codeClientMock.ExtendBundleFiles, expectedFile)
	}
	for _, expectedExclude := range expectedExcludes {
		assert.NotContains(t, codeClientMock.ExtendBundleFiles, expectedExclude)
	}
}

func Test_LoadIgnorePatternsWithoutIgnoreFilePresent(t *testing.T) {
	tempDir := t.TempDir()
	_, sc := setupTestScanner()

	ignorePatterns, _, err := sc.loadIgnorePatternsAndCountFiles(tempDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace")
	}

	assert.Equal(t, getDefaultIgnorePatterns(), ignorePatterns)
}

func Test_LoadIgnorePatternsAndCountFiles_RelativePathIgnores(t *testing.T) {
	testutil.UnitTest(t)
	tempDir := writeTestGitIgnore("", t)
	subDir := filepath.Join(tempDir, "evilfolder")
	_ = os.Mkdir(subDir, 0755)
	writeGitIgnoreIntoDir("*", t, subDir)
	expectedSubDirPattern := filepath.ToSlash(filepath.Join(subDir, "**/*"))

	sc := Scanner{}
	ignorePatterns, _, err := sc.loadIgnorePatternsAndCountFiles(tempDir)

	assert.NoError(t, err)
	assert.Contains(t, ignorePatterns, expectedSubDirPattern)
	assert.Len(t, ignorePatterns, len(getDefaultIgnorePatterns())+2)
}
