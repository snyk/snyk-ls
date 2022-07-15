package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestAddBundleHashToWorkspaceFolder(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder(".", "Test", snyk.NewTestScanner(), hover.NewTestHoverService())
	key := "bundleHash"
	value := "testHash"

	f.AddProductAttribute(snyk.ProductCode, key, value)

	assert.Equal(t, value, f.GetProductAttribute(snyk.ProductCode, key))
}

func Test_LoadIgnorePatternsWithIgnoreFilePresent(t *testing.T) {
	expectedPatterns, tempDir, _, _, _ := setupIgnoreWorkspace()
	defer os.RemoveAll(tempDir)
	f := NewFolder(tempDir, "Test", snyk.NewTestScanner(), hover.NewTestHoverService())

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
	f := NewFolder(tempDir, "Test", snyk.NewTestScanner(), hover.NewTestHoverService())

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
	f := NewFolder(tempDir, "Test", snyk.NewTestScanner(), hover.NewTestHoverService())

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
	f := NewFolder(tempDir, "Test", snyk.NewTestScanner(), hover.NewTestHoverService())

	walkedFiles, err := f.Files()
	if err != nil {
		t.Fatal(t, err, "Error while registering "+tempDir)
	}
	assert.NotContains(t, walkedFiles, ignoredFileInDir)
}

func Test_Scan_WhenCachedResults_shouldNotReScan(t *testing.T) {
	filePath, folderPath := code.FakeDiagnosticUri()
	scannerRecorder := snyk.NewTestScanner()
	scannerRecorder.Issues = []snyk.Issue{{AffectedFilePath: filePath}}
	f := NewFolder(folderPath, "Test", scannerRecorder, hover.NewTestHoverService())
	ctx := context.Background()

	f.ScanFile(ctx, filePath)
	f.ScanFile(ctx, filePath)

	assert.Equal(t, 1, scannerRecorder.Calls)
}

//todo: unignore this test
func Test_Scan_WhenCachedResultsButNoIssues_shouldNotReScan(t *testing.T) {
	t.Skip("this feature is not implemented yet")
	filePath, folderPath := code.FakeDiagnosticUri()
	scannerRecorder := snyk.NewTestScanner()
	scannerRecorder.Issues = []snyk.Issue{}
	f := NewFolder(folderPath, "Test", scannerRecorder, hover.NewTestHoverService())
	ctx := context.Background()

	f.ScanFile(ctx, filePath)
	f.ScanFile(ctx, filePath)

	assert.Equal(t, 1, scannerRecorder.Calls)
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

func TestProcessResults_SendsDiagnosticsAndHovers(t *testing.T) {
	t.Skipf("test this once we have uniform abstractions for hover & diagnostics")
	testutil.UnitTest(t)
	hoverService := hover.NewTestHoverService()
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hoverService)

	issues := []snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	}
	f.processResults(issues)
	// todo ideally there's a hover & diagnostic service that are symmetric and don't leak implementation details (e.g. channels)
	//assert.hoverService.GetAll()
}

func TestProcessResults_whenDifferentPaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewTestHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	})

	assert.Equal(t, 2, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.NotNil(t, f.documentDiagnosticCache.Get("path2"))
	assert.Len(t, f.documentDiagnosticCache.Get("path1"), 1)
	assert.Len(t, f.documentDiagnosticCache.Get("path2"), 1)
}

func TestProcessResults_whenSamePaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewTestHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path1"},
	})

	assert.Equal(t, 1, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.Len(t, f.documentDiagnosticCache.Get("path1"), 2)
}

func TestProcessResults_whenDifferentPaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewTestHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	})
	f.processResults([]snyk.Issue{{ID: "id3", AffectedFilePath: "path3"}})

	assert.Equal(t, 3, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.NotNil(t, f.documentDiagnosticCache.Get("path2"))
	assert.NotNil(t, f.documentDiagnosticCache.Get("path3"))
}

func TestProcessResults_whenSamePaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewTestHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path1"},
	})
	f.processResults([]snyk.Issue{{ID: "id3", AffectedFilePath: "path1"}})

	assert.Equal(t, 1, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.Len(t, f.documentDiagnosticCache.Get("path1"), 3)
}

func TestProcessResults_whenSamePathsAndDuplicateIssues_DeDuplicates(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewTestHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path1"},
	})
	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id3", AffectedFilePath: "path1"},
	})

	assert.Equal(t, 1, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.Len(t, f.documentDiagnosticCache.Get("path1"), 3)
}
