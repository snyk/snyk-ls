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
	"errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/rs/zerolog"
	gitconfig "github.com/snyk/snyk-ls/internal/git_config"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	InvalidBranchNameRegex, _ = regexp.Compile(`[^a-z0-9_\-]+`)
)

func HeadRefHashForRepo(repo *git.Repository) (string, error) {
	head, err := repo.Head()
	if err != nil {
		return "", err
	}
	commitHash := head.Hash().String()
	return commitHash, nil
}

func HeadRefHashForBranch(logger *zerolog.Logger, repoPath, branchName string) (string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to open repository")
		return "", err
	}
	branchReferenceName := plumbing.NewBranchReferenceName(branchName)

	ref, err := repo.Reference(branchReferenceName, true)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get reference")
		return "", err
	}

	commitHash := ref.Hash()
	return commitHash.String(), nil
}

func GitRepoFolderPath(logger *zerolog.Logger, folderPath string) (string, error) {
	repo, err := git.PlainOpen(folderPath)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to open repository: " + folderPath)
		return "", err
	}

	fsStorer, ok := repo.Storer.(*filesystem.Storage)
	if !ok {
		err = errors.New("repository storage is not a filesystem storage")
		logger.Error().Err(err).Msg("Faild to get fs storage for: " + folderPath)
		return "", err
	}
	repoPath := fsStorer.Filesystem().Root()
	if repoPath == "" {
		return "", errors.New("repository path is empty")
	}

	if !strings.HasSuffix(repoPath, ".git") {
		repoPath = filepath.Join(repoPath, ".git")
	}

	return repoPath, nil
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

func GetBaseBranchName(folderPath string) string {
	folderConfig, err := gitconfig.GetOrCreateFolderConfig(folderPath)
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
	repo, err := git.PlainOpen(repoPath)
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
