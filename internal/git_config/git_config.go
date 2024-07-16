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

package gitconfig

import (
	"fmt"

	"github.com/go-git/go-git/v5"
	config2 "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/config"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/internal/types"
)

const (
	mainSection   = "snyk"
	baseBranchKey = "baseBranch"
)

// GetOrCreateFolderConfig queries git for the folder config of the given path
func GetOrCreateFolderConfig(path string) (*types.FolderConfig, error) {
	repository, repoConfig, _, folderSection, err := getConfigSection(path)
	if err != nil {
		return nil, err
	}

	localBranches, err := getLocalBranches(repository)
	if err != nil {
		return nil, err
	}

	if len(localBranches) == 0 {
		return nil, fmt.Errorf("no local branches found")
	}

	// base branch is either overwritten or we return the default branch
	baseBranch := repoConfig.Init.DefaultBranch
	if folderSection.HasOption(baseBranchKey) {
		baseBranch = folderSection.Option(baseBranchKey)
	}

	if baseBranch == "" {
		if slices.Contains(localBranches, "main") {
			baseBranch = "main"
		} else if slices.Contains(localBranches, "master") {
			baseBranch = "master"
		} else {
			return nil, fmt.Errorf("could not determine base branch")
		}
	}

	return &types.FolderConfig{
		FolderPath:    path,
		BaseBranch:    baseBranch,
		LocalBranches: localBranches,
	}, nil
}

func getConfigSection(path string) (*git.Repository, *config2.Config, *config.Config, *config.Subsection, error) {
	repository, err := git.PlainOpen(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	repoConfig, err := repository.Config()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	raw := repoConfig.Raw
	section := raw.Section(mainSection)
	folderSection := section.Subsection(path)
	return repository, repoConfig, raw, folderSection, nil
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

func SetBaseBranch(config []types.FolderConfig) {
	for _, folderConfig := range config {
		_, _, _, subsection, err := getConfigSection(folderConfig.FolderPath)
		if err != nil {
			continue
		}
		subsection.AddOption(baseBranchKey, folderConfig.BaseBranch)
	}
}
