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

package storedconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"gopkg.in/ini.v1"

	config2 "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/config"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	mainSection          = "snyk"
	baseBranchKey        = "baseBranch"
	additionalParameters = "additionalParameters"
)

var (
	mutex sync.RWMutex
)

func getBaseBranch(repoConfig *config2.Config, folderSection *config.Subsection, localBranches []string) (string, error) {
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
			return "", fmt.Errorf("could not determine base branch")
		}
	}
	return baseBranch, nil
}

func getAdditionalParams(folderSection *config.Subsection) string {
	if folderSection.HasOption(additionalParameters) {
		return folderSection.Option(additionalParameters)
	}
	return ""
}

func getConfigSection(path string) (*git.Repository, *config2.Config, *config.Config, *config.Subsection, error) {
	mutex.Lock()
	// if DeleteEmptySnykSubsection fails, ignore error and attempt to reload config again
	_ = DeleteEmptySnykSubsection(path)
	mutex.Unlock()
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

func SetOption(logger *zerolog.Logger, folderPath, key string, value string) {
	// Don't set the config option if folder path or value is empty.
	// Setting empty options causes go-git to fail fetching config sections.
	if len(folderPath) == 0 || len(value) == 0 {
		return
	}
	repo, repoConfig, _, subsection, err := getConfigSection(folderPath)
	if err != nil {
		logger.Error().Err(err).Msg("could not get git config for folder " + folderPath)
		return
	}
	subsection.SetOption(key, value)
	err = repo.Storer.SetConfig(repoConfig)
	if err != nil {
		logger.Error().Err(err).Msgf("could not store %s=%s configuration for folder %s", key, value, folderPath)
	}
}

func GitFolderPath(folderPath string) (string, error) {
	repo, err := git.PlainOpen(folderPath)
	if err != nil {
		return "", fmt.Errorf("failed to open repository: %s %w", folderPath, err)
	}

	fsStorer, ok := repo.Storer.(*filesystem.Storage)
	if !ok {
		return "", fmt.Errorf("failed to get fs storage for: %s %w", folderPath, err)
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

// DeleteEmptySnykSubsection This is a migration function to be executed if empty subsections exists
func DeleteEmptySnykSubsection(path string) error {
	return DeleteSnykSubsection(path, `""`)
}

func DeleteSnykSubsection(path string, subsection string) error {
	gitFolderPath, err := GitFolderPath(path)
	if err != nil {
		return err
	}
	configPath := filepath.Join(gitFolderPath, "config")
	cfg, err := ini.Load(configPath)
	if err != nil {
		return err
	}
	// Construct the section name with the empty subsection
	sectionToDelete := fmt.Sprintf(`%s %s`, mainSection, subsection)
	section, err := cfg.GetSection(sectionToDelete)
	if section == nil || err != nil {
		return nil
	}
	cfg.DeleteSection(sectionToDelete)

	// make sure we are not writing empty config
	buf := new(bytes.Buffer)
	_, err = cfg.WriteTo(buf)
	if err != nil {
		return err
	}
	if buf.Len() == 0 {
		return nil
	}

	err = cfg.SaveToIndent(configPath, "\t")
	if err != nil {
		return fmt.Errorf("failed to save changes to git config %w", err)
	}
	return nil
}

func getFromGit(path string) (*types.FolderConfig, error) {
	repository, repoConfig, _, folderSection, err := getConfigSection(path)
	if err != nil {
		return nil, nil
	}

	localBranches, err := getLocalBranches(repository)
	if err != nil || len(localBranches) == 0 {
		return nil, err
	}

	folderConfig := types.FolderConfig{
		FolderPath:    path,
		LocalBranches: localBranches,
	}

	baseBranch, err := getBaseBranch(repoConfig, folderSection, localBranches)
	if err != nil {
		return &folderConfig, err
	}

	folderConfig.BaseBranch = baseBranch

	additionalParams := getAdditionalParams(folderSection)
	if len(additionalParams) > 0 {
		var additionalParamsFromGit []string
		err = json.Unmarshal([]byte(additionalParams), &additionalParamsFromGit)
		if err != nil {
			return &folderConfig, err
		}
		folderConfig.AdditionalParameters = append(folderConfig.AdditionalParameters, additionalParamsFromGit...)
	}
	return &folderConfig, nil
}

func SetupCustomTestRepo(t *testing.T, rootDir string, url string, targetCommit string, logger *zerolog.Logger) (string, error) {
	t.Helper()
	tempDir := filepath.Join(rootDir, util.Sha256First16Hash(t.Name()))
	assert.NoError(t, os.MkdirAll(tempDir, 0755))
	repoDir := "1"
	absoluteCloneRepoDir := filepath.Join(tempDir, repoDir)
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
		t.Fatal(err, "clone didn't work")
	}

	logger.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	logger.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	logger.Debug().Msg(string(output))
	return absoluteCloneRepoDir, err
}
