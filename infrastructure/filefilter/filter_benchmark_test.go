package filefilter_test

import (
	"os/exec"
	"testing"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/filefilter"
)

const remoteRepo = "https://github.com/juice-shop/juice-shop.git"
const remoteRepoHash = "9a0789b5ecb4ee76fe528b1860095e945f6302ac"

// BenchmarkFindNonIgnoredFiles will clone the remote repo and run the benchmark.
// This can be used manually during development to measure the performance of the file filtering.
func BenchmarkFindNonIgnoredFiles(b *testing.B) {
	b.Log("Cloning remoteRepo...")
	repo := cloneRepo(b, remoteRepo, remoteRepoHash)
	b.Log("Repo cloned")
	filter := filefilter.NewFileFilter(repo, config.New())
	b.ResetTimer() // reset timer to not include the clone time
	for i := 0; i < b.N; i++ {
		b.Log("Finding non ignored files in ", repo)
		filesCh := filter.FindNonIgnoredFiles()
		for range filesCh { // drain the channel
		}
		b.Log("Finished benchmark iteration ", i)
	}
}

func cloneRepo(tb testing.TB, repo string, checkout string) string {
	tb.Helper()
	tempDir := tb.TempDir()
	// git clone
	cmd := exec.Command("git", "clone", repo, tempDir)
	err := cmd.Run()
	if err != nil {
		tb.Fatal(err)
	}
	cmd = exec.Command("git", "checkout", checkout)
	cmd.Dir = tempDir
	err = cmd.Run()
	if err != nil {
		tb.Fatal(err)
	}

	return tempDir
}
