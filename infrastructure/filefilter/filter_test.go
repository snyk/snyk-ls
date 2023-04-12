package filefilter_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/infrastructure/filefilter"
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

func Test_FindNonIgnoredFiles(t *testing.T) {
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
			expectedFiles:     []string{"file1.js", "path/to/file2.js"},
			expectedExcludes:  []string{"file1.java", "file2.java", "path/to/file3.java"},
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
			name:             "Respects default ignore rules",
			repoPath:         t.TempDir(),
			ignoreFilePath:   ".gitignore",
			expectedFiles:    []string{"file1.java"},
			expectedExcludes: []string{".git/file", ".svn/file", ".hg/file", ".bzr/file", ".DS_Store/file"},
		},
		{
			name:              "Respects negation rules",
			repoPath:          t.TempDir(),
			ignoreFilePath:    ".gitignore",
			ignoreFileContent: ("*.java\n") + ("!file1.java\n") + ("!path/to/file3.java\n"),
			expectedFiles:     []string{"file1.java", "path/to/file3.java"},
			expectedExcludes:  []string{"file2.java"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			setupIgnoreFilesTest(t, testCase)

			var files []string
			for f := range filefilter.FindNonIgnoredFiles(testCase.repoPath) {
				files = append(files, f)
			}

			assertFilesFiltered(t, testCase, files)
		})
	}
}

func Test_FindNonIgnoredFiles_MultipleWorkDirs(t *testing.T) {
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

	for _, testCase := range testCases {
		files := collectFilteredFiles(testCase.repoPath)
		assertFilesFiltered(t, testCase, files)
	}
}

func collectFilteredFiles(repoPath string) []string {
	var files []string
	for f := range filefilter.FindNonIgnoredFiles(repoPath) {
		files = append(files, f)
	}
	return files
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

func assertFilesFiltered(t *testing.T, testCase ignoreFilesTestCase, files []string) {
	t.Helper()
	for _, expectedFile := range testCase.expectedFiles {
		assert.Contains(t, files, filepath.Join(testCase.repoPath, expectedFile))
	}
	for _, expectedExclude := range testCase.expectedExcludes {
		assert.NotContains(t, files, filepath.Join(testCase.repoPath, expectedExclude))
	}
}
