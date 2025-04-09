package filefilter_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/infrastructure/filefilter"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

type ignoreFilesTestCase struct {
	// The name of the test case. Will be used as the test name in t.Run()
	name string
	// Path to the repo to be scanned
	repoPath string
	// Map of ignore files. Key is the relative path to the repoPath, value is the content of the file.
	ignoreFiles map[string]string
	// Will assert that these files are in the list of files to be uploaded. Files paths are relative to the repoPath
	expectedFiles []string
	// Will assert that these files are not in the list of files to be uploaded. Files paths are relative to the repoPath
	expectedExcludes []string
}

func Test_FindNonIgnoredFiles(t *testing.T) {
	c := testutil.UnitTest(t)
	cases := testCases(t)

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			setupIgnoreFilesTest(t, testCase)

			filter := filefilter.NewFileFilter(testCase.repoPath, c.Logger())
			var files []string
			for f := range filter.FindNonIgnoredFiles(getTestTracker()) {
				files = append(files, f)
			}
			assertFilesFiltered(t, testCase, files)

			t.Run("2nd call should return the same files", func(t *testing.T) {
				var files2 []string
				for f := range filter.FindNonIgnoredFiles(getTestTracker()) {
					files2 = append(files2, f)
				}
				assert.ElementsMatch(t, files, files2)
			})
		})
	}
}

func Test_FindNonIgnoredFiles_MultipleWorkDirs(t *testing.T) {
	c := testutil.UnitTest(t)
	// Arrange - set 2 repos with different ignore rules. Each repo will have foo.go and bar.go files.
	// In repo A, foo.go will be ignored, and in repo B, bar.go will be ignored.
	tempDir := t.TempDir()
	cases := []ignoreFilesTestCase{{
		repoPath:         filepath.Join(tempDir, "A"),
		ignoreFiles:      map[string]string{".gitignore": "bar.go\n"},
		expectedFiles:    []string{"foo.go"},
		expectedExcludes: []string{"bar.go"},
	}, {
		repoPath:         filepath.Join(tempDir, "B"),
		ignoreFiles:      map[string]string{".gitignore": "foo.go\n"},
		expectedFiles:    []string{"bar.go"},
		expectedExcludes: []string{"foo.go"},
	}}
	for _, testCase := range cases {
		setupIgnoreFilesTest(t, testCase)
	}

	for _, testCase := range cases {
		// Act
		nonIgnoredFiles := filefilter.FindNonIgnoredFiles(
			getTestTracker(),
			testCase.repoPath,
			c.Logger(),
		)
		files := util.ChannelToSlice(nonIgnoredFiles)

		// Assert
		assertFilesFiltered(t, testCase, files)
	}
}

func Test_FindNonIgnoredFiles_TrailingSlashPath(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	// Ignore file is in root
	// Folder Path has a trailing backslash
	// Files are included in sub dirs
	tempDir := t.TempDir()
	testCase := ignoreFilesTestCase{
		repoPath:         filepath.Join(tempDir, string(filepath.Separator)),
		ignoreFiles:      map[string]string{".gitignore": "bar.go\n"},
		expectedFiles:    []string{filepath.Join(tempDir, "A", "B", "foo.go")},
		expectedExcludes: []string{filepath.Join(tempDir, "A", "B", "bar.go")},
	}
	setupIgnoreFilesTest(t, testCase)

	// Act
	nonIgnoredFiles := filefilter.FindNonIgnoredFiles(
		getTestTracker(),
		testCase.repoPath,
		c.Logger(),
	)
	files := util.ChannelToSlice(nonIgnoredFiles)

	// Assert
	assertFilesFiltered(t, testCase, files)
}

func getTestTracker() *progress.Tracker {
	return progress.NewTestTracker(make(chan types.ProgressParams, 100000), make(chan bool, 1))
}

func Test_FindNonIgnoredFile_FilesChanged_ReturnsCorrectResults(t *testing.T) {
	// Arrange - set up repo
	c := testutil.UnitTest(t)

	repoFolder := t.TempDir()
	type fileChangesTestCase struct {
		ignoreFilesTestCase
		expectedAddedFiles    []string
		expectedAddedExcludes []string
	}
	testCase := fileChangesTestCase{
		ignoreFilesTestCase: ignoreFilesTestCase{
			repoPath:         repoFolder,
			ignoreFiles:      map[string]string{".gitignore": "*.go\n"},
			expectedFiles:    []string{"foo.js", "bar.js"},
			expectedExcludes: []string{"foo.go", "bar.go"},
		},
		expectedAddedFiles:    []string{"foo2.js", "bar2.js"},
		expectedAddedExcludes: []string{"foo2.go", "bar2.go"},
	}
	setupIgnoreFilesTest(t, testCase.ignoreFilesTestCase)
	fileFilter := filefilter.NewFileFilter(repoFolder, c.Logger())
	originalFilteredFiles := util.ChannelToSlice(fileFilter.FindNonIgnoredFiles(getTestTracker())) // Calling it a first time

	// Act - Changing folder content
	filesToCreate := append(testCase.expectedAddedFiles, testCase.expectedAddedExcludes...)
	createFiles(t, repoFolder, filesToCreate)
	newFilteredFiles := util.ChannelToSlice(fileFilter.FindNonIgnoredFiles(getTestTracker()))

	// Assert - Make sure the added files have been filtered correctly
	assert.NotEqual(t, originalFilteredFiles, newFilteredFiles)
	testCase.expectedFiles = append(testCase.expectedFiles, testCase.expectedAddedFiles...)
	testCase.expectedExcludes = append(testCase.expectedExcludes, testCase.expectedAddedExcludes...)
	assertFilesFiltered(t, testCase.ignoreFilesTestCase, newFilteredFiles)
}

func testCases(t *testing.T) []ignoreFilesTestCase {
	t.Helper()
	cases := []ignoreFilesTestCase{
		{
			name:     "Does not ignore files when no ignored file is present",
			repoPath: t.TempDir(),
			ignoreFiles: map[string]string{
				".gitignore": "temp\n",
			},
			expectedFiles:    []string{"file1.java", "file2.java"},
			expectedExcludes: []string{},
		},
		{
			name:             "Does not panic when folder is empty",
			repoPath:         t.TempDir(),
			ignoreFiles:      map[string]string{},
			expectedFiles:    []string{},
			expectedExcludes: []string{},
		},
		{
			name:     "Respects ignore rules",
			repoPath: t.TempDir(),
			ignoreFiles: map[string]string{
				".gitignore": "*.java\n",
			},
			expectedFiles:    []string{"file1.js", "path/to/file2.js"},
			expectedExcludes: []string{"file1.java", "file2.java", "path/to/file3.java"},
		},
		{
			name:     "Respects .snyk ignore rules",
			repoPath: t.TempDir(),
			ignoreFiles: map[string]string{
				".snyk": `
exclude:
  code:
    - path/to/code/ignore1
    - path/to/code/ignore2
  global:
    - path/to/global/ignore1
    - path/to/global/ignore2
`,
			},
			expectedFiles: []string{"path/to/code/notIgnored.java"},
			expectedExcludes: []string{
				"path/to/code/ignore1/ignoredFile.java",
				"path/to/code/ignore2/ignoredFile.java",
				"path/to/global/ignore1/ignoredFile.java",
				"path/to/global/ignore2/ignoredFile.java",
			},
		},
		{
			name:     "Respects default ignore rules",
			repoPath: t.TempDir(),
			ignoreFiles: map[string]string{
				".gitignore": "",
			},
			expectedFiles:    []string{"file1.java"},
			expectedExcludes: []string{".git/file", ".svn/file", ".hg/file", ".bzr/file", ".DS_Store/file"},
		},
		{
			name:     "Respects negation rules",
			repoPath: t.TempDir(),
			ignoreFiles: map[string]string{
				".gitignore": ("*.java\n") + ("!file1.java\n") + ("!path/to/file3.java\n"),
			},
			expectedFiles:    []string{"file1.java", "path/to/file3.java"},
			expectedExcludes: []string{"file2.java"},
		},
		{
			name:     "Respects negation rules for files inside folders",
			repoPath: t.TempDir(),
			ignoreFiles: map[string]string{
				".gitignore": ("/path/*\n") + ("!/path/file2.java\n"),
			},
			expectedFiles:    []string{"file1.java", "path/file2.java"},
			expectedExcludes: []string{"path/file3.java", "path/to/file5.java"},
		},
		{
			name:     "Nested ignore rules",
			repoPath: t.TempDir(),
			ignoreFiles: map[string]string{
				".gitignore":         "*.java\n",
				"path/to/.gitignore": "*.js\n",
			},
			expectedFiles:    []string{"file1.js", "file1.txt", "path/to/file2.txt"},
			expectedExcludes: []string{"file1.java", "path/to/file1.js", "path/to/nested/file2.js"},
		},
		{
			name:     "Ignored folder with negation rules",
			repoPath: t.TempDir(),
			ignoreFiles: map[string]string{
				".gitignore":   "/a/",
				"a/.gitignore": "!*.txt",
			},
			expectedFiles:    []string{"file1.js"},
			expectedExcludes: []string{"a/file1.txt", "a/file2.js"},
		},
	}
	return cases
}

func setupIgnoreFilesTest(t *testing.T, testCase ignoreFilesTestCase) {
	t.Helper()
	testutil.UnitTest(t)
	allFiles := append(testCase.expectedFiles, testCase.expectedExcludes...)

	for ignoreFilePath, ignoreFileContent := range testCase.ignoreFiles {
		ignoreFileAbsPath := filepath.Join(testCase.repoPath, ignoreFilePath)
		testsupport.CreateFileOrFail(t, ignoreFileAbsPath, []byte(ignoreFileContent))
	}
	createFiles(t, testCase.repoPath, allFiles)
}

func createFiles(t *testing.T, repoPath string, allFiles []string) {
	t.Helper()
	for _, path := range allFiles {
		absPath := path
		if !filepath.IsAbs(path) {
			absPath = filepath.Join(repoPath, path)
		}
		testsupport.CreateFileOrFail(t, absPath, []byte("some content to avoid skipping"))
	}
}

// assertFilesFiltered asserts that the "expectedFile"s are contained in the files slice,
// and the "expectedExclude" are not.
func assertFilesFiltered(t *testing.T, testCase ignoreFilesTestCase, files []string) {
	t.Helper()
	for _, expectedFile := range testCase.expectedFiles {
		expectedFileAbsPath := expectedFile
		if !filepath.IsAbs(expectedFileAbsPath) {
			expectedFileAbsPath = filepath.Join(testCase.repoPath, expectedFile)
		}
		assert.Contains(t, files, expectedFileAbsPath)
	}
	for _, expectedExclude := range testCase.expectedExcludes {
		expectedExcludeAbsPath := expectedExclude
		if !filepath.IsAbs(expectedExcludeAbsPath) {
			expectedExcludeAbsPath = filepath.Join(testCase.repoPath, expectedExclude)
		}
		assert.NotContains(t, files, expectedExcludeAbsPath)
	}
}

func Test_FindNonIgnoredFiles_IgnoredFolderContainsNestedNegationRules_NestedRulesIgnored(t *testing.T) {
	// Arrange
	c := testutil.UnitTest(t)
	repoFolder := t.TempDir()
	testsupport.CreateFileOrFail(t, filepath.Join(repoFolder, ".gitignore"), []byte(".gitignore\n/a/\n"))
	testsupport.CreateFileOrFail(t, filepath.Join(repoFolder, "a", ".gitignore"), []byte("!b.txt"))
	testsupport.CreateFileOrFail(t, filepath.Join(repoFolder, "a", "b.txt"), []byte("some content"))
	fileFilter := filefilter.NewFileFilter(repoFolder, c.Logger())

	// Act
	filteredFiles := util.ChannelToSlice(fileFilter.FindNonIgnoredFiles(getTestTracker()))

	// Assert
	assert.Empty(t, filteredFiles)
}
