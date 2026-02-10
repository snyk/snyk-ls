/*
 * © 2024 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package vcs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

var (
	InvalidBranchNameRegex, _ = regexp.Compile(`[^a-z0-9_\-]+`)
)

// GitRepoRoot resolves the git repository root directory from any path within
// the repository (including subfolders). It walks up parent directories until
// a .git entry (directory or file) is found, without opening the repository.
// This avoids holding git packfile handles that can cause cleanup failures on Windows.
func GitRepoRoot(path types.FilePath) (types.FilePath, error) {
	p, err := filepath.Abs(string(path))
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(p, ".git")); err == nil {
			return types.FilePath(p), nil
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", fmt.Errorf("repository does not exist")
		}
		p = parent
	}
}

func HeadRefHashForRepo(repo *git.Repository) (string, error) {
	head, err := repo.Head()
	if err != nil {
		return "", err
	}
	commitHash := head.Hash().String()
	return commitHash, nil
}

func HeadRefHashForBranch(logger *zerolog.Logger, repoPath types.FilePath, branchName string) (string, error) {
	repo, err := git.PlainOpenWithOptions(string(repoPath), &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		logger.Error().Err(err).Msg("Failed to open repository")
		return "", err
	}
	branchReferenceName := plumbing.NewBranchReferenceName(branchName)

	ref, err := repo.Reference(branchReferenceName, true)
	if err != nil {
		logger.Error().Err(err).Str("branchReferenceName", branchReferenceName.String()).Msg("Failed to get reference")
		return "", err
	}

	commitHash := ref.Hash()
	return commitHash.String(), nil
}

func hasUncommitedChanges(repo *git.Repository) bool {
	worktree, err := repo.Worktree()
	if err != nil {
		return false
	}

	status, err := worktree.Status()
	if err != nil {
		return false
	}

	for _, st := range status {
		if st.Staging != git.Unmodified || st.Worktree != git.Unmodified {
			return true
		}
	}
	return false
}

func GetBaseBranchName(conf configuration.Configuration, folderPath types.FilePath, logger *zerolog.Logger) string {
	folderConfig, err := storedconfig.GetOrCreateFolderConfig(conf, folderPath, logger)
	if err != nil {
		return "master"
	}
	return folderConfig.BaseBranch
}

func NormalizeBranchName(branchName string) string {
	normalized := strings.TrimSpace(branchName)
	normalized = strings.ToLower(normalized)
	normalized = strings.ReplaceAll(normalized, " ", "_")

	normalized = InvalidBranchNameRegex.ReplaceAllString(normalized, "")

	return normalized
}

func targetBranchExists(branchName plumbing.ReferenceName, repo *git.Repository) bool {
	branchExists := false
	referenceList, err := repo.References()
	if err != nil {
		return false
	}
	defer referenceList.Close()

	_ = referenceList.ForEach(func(reference *plumbing.Reference) error {
		if reference.Name() == branchName {
			branchExists = true
		}
		return nil
	})

	return branchExists
}

func resetAndCheckoutRepo(repoPath string, branchName plumbing.ReferenceName) (*git.Repository, error) {
	repo, err := git.PlainOpenWithOptions(repoPath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}
	workTree, err := repo.Worktree()
	if err != nil {
		return nil, err
	}

	err = workTree.Reset(&git.ResetOptions{Mode: git.HardReset})
	if err != nil {
		return nil, err
	}

	err = workTree.Checkout(&git.CheckoutOptions{Force: true, Branch: branchName})
	if err != nil {
		return nil, err
	}
	return repo, nil
}
