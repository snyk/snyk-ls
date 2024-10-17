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
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/otiai10/copy"
	"github.com/rs/zerolog"
)

func Clone(logger *zerolog.Logger, srcRepoPath string, destinationPath string, targetBranchName string) (*git.Repository, error) {
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
		logger.Debug().Msg("Clone operation failed. Maybe repo is in detached HEAD state?")
		targetRepo := cloneRepoWithFsCopy(logger, srcRepoPath, destinationPath, targetBranchReferenceName)
		if targetRepo == nil {
			return nil, err
		}
		return targetRepo, nil
	}

	// Patch Origin Remote for the cloned repo. This is only necessary if we use checkout since the remote origin URL will be the srcRepoPath
	err = patchClonedRepoRemoteOrigin(logger, srcRepoPath, clonedRepo)
	if err != nil {
		logger.Error().Err(err).Msgf("Could not patch origin remote url in cloned repo %s", destinationPath)
	}
	return clonedRepo, nil
}

func patchClonedRepoRemoteOrigin(logger *zerolog.Logger, srcRepoPath string, clonedRepo *git.Repository) error {
	srcRepo, err := git.PlainOpen(srcRepoPath)
	if err != nil {
		logger.Error().Err(err).Msgf("Could not open source repo: %s", srcRepoPath)
		return err
	}

	srcConfig, err := srcRepo.Config()
	if err != nil {
		logger.Error().Err(err).Msg("Could not get config from source repo")
		return err
	}

	var originURLs []string
	if origin, ok := srcConfig.Remotes["origin"]; ok && len(origin.URLs) > 0 {
		originURLs = origin.URLs
	} else {
		logger.Warn().Msg("Source repo has no origin remote or no URLs. Skipping patching clone origin")
		return nil
	}

	clonedConfig, err := clonedRepo.Config()
	if err != nil {
		logger.Error().Err(err).Msg("Could not get config from cloned repo")
		return err
	}

	if origin, ok := clonedConfig.Remotes["origin"]; ok {
		origin.URLs = originURLs
	} else {
		clonedConfig.Remotes["origin"] = &config.RemoteConfig{
			Name: "origin",
			URLs: originURLs,
		}
	}

	err = clonedRepo.Storer.SetConfig(clonedConfig)
	if err != nil {
		logger.Error().Err(err).Msg("Could not set config for cloned repo")
		return err
	}

	return nil
}

func cloneRepoWithFsCopy(logger *zerolog.Logger, srcRepoPath string, destinationRepoPath string, targetBranchReferenceName plumbing.ReferenceName) *git.Repository {
	repo, err := git.PlainOpen(srcRepoPath)
	if err != nil {
		return nil
	}
	branchExists := targetBranchExists(targetBranchReferenceName, repo)
	if !branchExists {
		logger.Debug().Msgf("Branch %s does not exist in repo %s. Exiting", targetBranchReferenceName.Short(), srcRepoPath)
		return nil
	}
	gitSrcRepoPath := filepath.Join(srcRepoPath, ".git")
	gitDestRepoPath := filepath.Join(destinationRepoPath, ".git")
	logger.Debug().Msgf("Attemping to copy repo .git folder from: %s to: %s ", gitSrcRepoPath, gitDestRepoPath)
	err = copy.Copy(gitSrcRepoPath, gitDestRepoPath)
	if err != nil {
		logger.Debug().Err(err).Msgf("Copy operation failed. Exiting")
		return nil
	}
	logger.Debug().Msg("Copy operation succeeded")
	targetRepo, checkOutErr := resetAndCheckoutRepo(destinationRepoPath, targetBranchReferenceName)
	if checkOutErr != nil {
		logger.Debug().Err(checkOutErr).Msgf("Could not checkout target branch %s. Exiting", targetBranchReferenceName.Short())
		return nil
	}
	return targetRepo
}

func LocalRepoHasChanges(logger *zerolog.Logger, repoPath string) (bool, error) {
	currentRepo, err := git.PlainOpen(repoPath)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to open current repo " + repoPath)
		return false, err
	}

	branchName := GetBaseBranchName(repoPath)

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
