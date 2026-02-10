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
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
)

func Clone(logger *zerolog.Logger, srcRepoPath types.FilePath, destinationPath types.FilePath, targetBranchName string) (*git.Repository, error) {
	// Resolve the git root in case srcRepoPath is a subfolder of the actual repository
	resolvedRoot, err := GitRepoRoot(srcRepoPath)
	if err != nil {
		logger.Error().Err(err).Msgf("Could not resolve git root for: %s", srcRepoPath)
		return nil, err
	}
	if resolvedRoot != srcRepoPath {
		logger.Debug().
			Str("srcRepoPath", string(srcRepoPath)).
			Str("resolvedRoot", string(resolvedRoot)).
			Msg("resolved git root from subfolder path")
	}

	targetBranchReferenceName := plumbing.NewBranchReferenceName(targetBranchName)
	clonedRepo, err := git.PlainClone(string(destinationPath), false, &git.CloneOptions{
		URL:           string(resolvedRoot),
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
		targetRepo := cloneRepoWithFsCopy(logger, resolvedRoot, destinationPath, targetBranchReferenceName)
		if targetRepo == nil {
			return nil, err
		}
		return targetRepo, nil
	}

	// Patch Origin Remote for the cloned repo. This is only necessary if we use checkout since the remote origin URL will be the srcRepoPath
	err = patchClonedRepoRemoteOrigin(logger, resolvedRoot, clonedRepo)
	if err != nil {
		logger.Error().Err(err).Msgf("Could not patch origin remote url in cloned repo %s", destinationPath)
	}

	logger.Debug().
		Str("srcRepoPath", string(srcRepoPath)).
		Str("destinationPath", string(destinationPath)).
		Str("targetBranchName", targetBranchName).
		Msg("successfully cloned base branch")

	return clonedRepo, nil
}

func patchClonedRepoRemoteOrigin(logger *zerolog.Logger, srcRepoPath types.FilePath, clonedRepo *git.Repository) error {
	srcRepo, err := git.PlainOpenWithOptions(string(srcRepoPath), &git.PlainOpenOptions{DetectDotGit: true})
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

func cloneRepoWithFsCopy(logger *zerolog.Logger, srcRepoPath types.FilePath, destinationRepoPath types.FilePath, targetBranchReferenceName plumbing.ReferenceName) *git.Repository {
	repo, err := git.PlainOpenWithOptions(string(srcRepoPath), &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil
	}
	branchExists := targetBranchExists(targetBranchReferenceName, repo)
	if !branchExists {
		logger.Debug().Msgf("Branch %s does not exist in repo %s. Exiting", targetBranchReferenceName.Short(), srcRepoPath)
		return nil
	}
	var gitSrcRepoPath = filepath.Join(string(srcRepoPath), ".git")
	gitDestRepoPath := filepath.Join(string(destinationRepoPath), ".git")
	logger.Debug().Msgf("Attemping to copy repo .git folder from: %s to: %s ", gitSrcRepoPath, gitDestRepoPath)
	err = copy.Copy(gitSrcRepoPath, gitDestRepoPath)
	if err != nil {
		logger.Debug().Err(err).Msgf("Copy operation failed. Exiting")
		return nil
	}
	logger.Debug().Msg("Copy operation succeeded")
	targetRepo, checkOutErr := resetAndCheckoutRepo(string(destinationRepoPath), targetBranchReferenceName)
	if checkOutErr != nil {
		logger.Debug().Err(checkOutErr).Msgf("Could not checkout target branch %s. Exiting", targetBranchReferenceName.Short())
		return nil
	}

	logger.Debug().
		Str("branch", targetBranchReferenceName.Short()).
		Msg("successfully cloned base branch via FS copy")

	return targetRepo
}

func LocalRepoHasChanges(conf configuration.Configuration, logger *zerolog.Logger, repoPath types.FilePath) (bool, error) {
	currentRepo, err := git.PlainOpenWithOptions(string(repoPath), &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		logger.Error().Err(err).Msg(string("Failed to open current repo " + repoPath))
		return false, err
	}

	branchName := GetBaseBranchName(conf, repoPath, logger)

	currentRepoBranch, err := currentRepo.Head()
	if err != nil {
		logger.Error().Err(err).Msg(string("Failed to get HEAD for " + repoPath))
		return false, err
	}

	if currentRepoBranch.Name().Short() != branchName || hasUncommitedChanges(currentRepo) {
		return true, nil
	}

	return false, nil
}
