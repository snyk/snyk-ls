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
	"github.com/rs/zerolog"
)

func Clone(repoPath string, destinationPath string, branchName string, logger *zerolog.Logger, gitOps GitOps) (*git.Repository, error) {
	baseBranchName := plumbing.NewBranchReferenceName(branchName)
	currentRepo, err := gitOps.PlainOpen(repoPath)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to open current repo in go-git " + repoPath)
		return nil, err
	}

	currentRepoBranch, err := gitOps.Head(currentRepo)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get HEAD for " + repoPath)
		return nil, err
	}

	if currentRepoBranch.Name() == baseBranchName {
		logger.Info().Msg("Current branch is the same as base. Skipping cloning")
		return nil, nil
	}

	clonedRepo, err := gitOps.PlainClone(destinationPath, false, &git.CloneOptions{
		URL:           repoPath,
		ReferenceName: baseBranchName,
		SingleBranch:  true,
	})

	if err != nil {
		logger.Error().Err(err).Msg("Failed to clone base in temp repo with go-git " + destinationPath)
		return nil, err
	}

	return clonedRepo, nil
}

func GetCommitHashForRepo(repo *git.Repository) (string, error) {
	head, err := repo.Head()
	if err != nil {
		return "", err
	}
	commitHash := head.Hash().String()
	return commitHash, nil
}
