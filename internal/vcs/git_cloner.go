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
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	copy2 "github.com/otiai10/copy"
	"github.com/rs/zerolog"
	"path/filepath"
	"strings"
)

func Clone(srcRepoPath string, destinationPath string, targetBranchName string, logger *zerolog.Logger) (*git.Repository, error) {
	targetBranchReferenceName := plumbing.NewBranchReferenceName(targetBranchName)
	clonedRepo, err := git.PlainClone(destinationPath, false, &git.CloneOptions{
		URL:           srcRepoPath,
		ReferenceName: targetBranchReferenceName,
		SingleBranch:  true,
	})

	if err != nil {
		// errors.Is doesn't work for plumbing.ErrReferenceNotFound
		if !strings.Contains(err.Error(), "reference not found") {
			logger.Error().Err(err).Msgf("Could not clone base branch: %s in temp repo: %s", targetBranchReferenceName, destinationPath)
			return nil, err
		}
		// Repository might be in a detached head state.
		// We will copy the repo to target repo
		logger.Debug().Msg("Clone operation failed. Maybe repo is in detached HEAD mode?")
		targetRepo := cloneRepoWithFsCopy(srcRepoPath, destinationPath, targetBranchName, logger, targetBranchReferenceName)
		if targetRepo == nil {
			return nil, err
		}
		return targetRepo, nil
	}
	return clonedRepo, nil
}

func cloneRepoWithFsCopy(srcRepoPath string, destinationPath string, targetBranchName string, logger *zerolog.Logger, targetBranchReferenceName plumbing.ReferenceName) *git.Repository {
	repo, err := git.PlainOpen(srcRepoPath)
	if err != nil {
		return nil
	}
	branchExists := targetBranchExists(targetBranchReferenceName, repo)
	if !branchExists {
		logger.Debug().Msgf("Branch %s does not exist in repo %s. Exiting", targetBranchName, srcRepoPath)
		return nil
	}
	gitSrcRepoPath := filepath.Join(srcRepoPath, ".git")
	gitDestRepoPath := filepath.Join(destinationPath, ".git")
	logger.Debug().Msgf("Attemping to copy repo %s from %s to", gitSrcRepoPath, gitDestRepoPath)
	err = copy2.Copy(gitSrcRepoPath, gitDestRepoPath)
	if err != nil {
		logger.Debug().Err(err).Msgf("Copy operation failed. Exiting")
		return nil
	}
	logger.Debug().Msg("Copy operation succeeded")
	targetRepo, checkOutErr := resetAndCheckoutRepo(destinationPath, targetBranchReferenceName)
	if checkOutErr != nil {
		logger.Debug().Err(checkOutErr).Msgf("Could not force checkout target branch %s. Exiting", targetBranchName)
		return nil
	}
	return targetRepo
}

func ShouldClone(repoPath string, logger *zerolog.Logger, branchName string) (bool, error) {
	currentRepo, err := git.PlainOpen(repoPath)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to open current repo in go-git " + repoPath)
		return false, err
	}

	currentRepoBranch, err := currentRepo.Head()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get HEAD for " + repoPath)
		return false, err
	}

	if currentRepoBranch.Name().Short() != branchName || hasUncommitedChanges(currentRepo) {
		return true, nil
	}

	return false, nil
}
