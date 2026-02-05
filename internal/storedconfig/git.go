/*
 * © 2024-2025 Snyk Limited
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

// Package storedconfig implements stored configuration functionality
package storedconfig

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func getBaseBranch(repository *git.Repository, localBranches []string) (string, error) {
	repoConfig, err := repository.Config()
	if err != nil {
		return "", err
	}

	// Try the default branch ...
	baseBranch := repoConfig.Init.DefaultBranch

	// ... fall back to common defaults if no default branch is set
	if baseBranch == "" {
		if slices.Contains(localBranches, "main") {
			baseBranch = "main"
		} else if slices.Contains(localBranches, "master") {
			baseBranch = "master"
		} else {
			return "", fmt.Errorf("could not determine base branch")
		}
	}

	return baseBranch, nil
}

func getLocalBranches(repository *git.Repository) ([]string, error) {
	localBranchRefs, err := repository.Branches()
	if err != nil {
		return nil, err
	}
	localBranches := []string{}
	err = localBranchRefs.ForEach(func(reference *plumbing.Reference) error {
		localBranches = append(localBranches, reference.Name().Short())
		return nil
	})
	if err != nil {
		return nil, err
	}
	return localBranches, nil
}

func enrichFromGit(logger *zerolog.Logger, folderConfig *types.StoredFolderConfig) *types.StoredFolderConfig {
	l := logger.With().Str("method", "enrichFromGit").Logger()

	repository, err := git.PlainOpen(string(folderConfig.FolderPath))
	if err != nil {
		return folderConfig // Probably not a git repo and that's okay
	}

	// Always get the fresh local branches
	localBranches, err := getLocalBranches(repository)
	if err != nil {
		// Don't fail completely if we can't determine local branches
		// We should still try to get the base branch from the repo config
		l.Debug().Err(err).Msgf("could not get local branches for path %s", folderConfig.FolderPath)
	} else {
		folderConfig.LocalBranches = localBranches
	}

	// Only determine the base branch if not set (potentially overwritten) in the stored config
	if folderConfig.BaseBranch == "" {
		baseBranch, err := getBaseBranch(repository, localBranches)
		if err != nil {
			// Don't fail completely if we can't determine base branch
			// We still have valid local branches that should be used
			// Just skip setting the base branch
			l.Debug().Err(err).Msgf("could not determine base branch for path %s", folderConfig.FolderPath)
		} else {
			folderConfig.BaseBranch = baseBranch
		}
	}

	return folderConfig
}

func SetupCustomTestRepo(t *testing.T, rootDir types.FilePath, url string, targetCommit string, logger *zerolog.Logger, useRootDirDirectly bool) (types.FilePath, error) {
	t.Helper()
	tempDir := filepath.Join(string(rootDir), util.Sha256First16Hash(t.Name()))
	repoDir := "1"
	absoluteCloneRepoDir := filepath.Join(tempDir, repoDir)

	if useRootDirDirectly {
		tempDir = string(rootDir)
		absoluteCloneRepoDir = filepath.Join(tempDir, repoDir)
		stat, err := os.Stat(absoluteCloneRepoDir)
		if err == nil && stat.IsDir() {
			// exists, return
			return types.FilePath(absoluteCloneRepoDir), nil
		}
	}
	assert.NoError(t, os.MkdirAll(tempDir, 0755))
	cmd := []string{"clone", "-v", url, repoDir}
	logger.Debug().Interface("cmd", cmd).Msg("clone command")
	clone := exec.Command("git", cmd...)
	clone.Dir = tempDir
	reset := exec.Command("git", "reset", "--hard", targetCommit)
	reset.Dir = absoluteCloneRepoDir

	clean := exec.Command("git", "clean", "--force")
	clean.Dir = absoluteCloneRepoDir

	output, err := clone.CombinedOutput()
	if err != nil {
		t.Log(string(output))
		t.Fatal(err, "clone didn't work")
	}

	logger.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	logger.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	logger.Debug().Msg(string(output))
	return types.FilePath(absoluteCloneRepoDir), err
}
