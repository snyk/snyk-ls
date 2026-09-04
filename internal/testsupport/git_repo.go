package testsupport

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const defaultTestGitOrigin = "https://github.com/org/repo.git"

// GitCommandForTestRepo returns a git command scoped to dir with an env that
// does not inherit host worktree/config overrides (see GitEnvWithoutInheritedRepoConfig).
func GitCommandForTestRepo(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = GitEnvWithoutInheritedRepoConfig(os.Environ())
	return cmd
}

// RunGitForTestRepo runs git in dir and fails the test on non-zero exit.
func RunGitForTestRepo(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := GitCommandForTestRepo(dir, args...)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
}

// InitTestGitRepo creates a git repository with one commit under dir.
// Conventions match internal/folderconfig/git_test.go initializeTestGitRepo.
func InitTestGitRepo(t *testing.T, dir string) {
	t.Helper()
	RunGitForTestRepo(t, dir, "init", "--initial-branch=main")
	RunGitForTestRepo(t, dir, "config", "commit.gpgsign", "false")

	seed := filepath.Join(dir, "seed.txt")
	require.NoError(t, os.WriteFile(seed, []byte("seed"), 0600))
	RunGitForTestRepo(t, dir, "add", "seed.txt")

	cmd := GitCommandForTestRepo(dir, "commit", "-m", "init")
	cmd.Env = append(cmd.Env,
		"GIT_AUTHOR_NAME=Snyk LS Test",
		"GIT_AUTHOR_EMAIL=snyk-ls-test@example.invalid",
		"GIT_COMMITTER_NAME=Snyk LS Test",
		"GIT_COMMITTER_EMAIL=snyk-ls-test@example.invalid",
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
}

// InitTestGitRepoWithOrigin creates InitTestGitRepo and adds an origin remote.
func InitTestGitRepoWithOrigin(t *testing.T, dir string, originURL string) {
	t.Helper()
	InitTestGitRepo(t, dir)
	if originURL == "" {
		originURL = defaultTestGitOrigin
	}
	RunGitForTestRepo(t, dir, "remote", "add", "origin", originURL)
}
