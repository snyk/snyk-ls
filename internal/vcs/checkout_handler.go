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
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
)

type CheckoutHandler struct {
	baseFolderPath string
	repository     *git.Repository
	cleanupFunc    func()
	mutex          sync.Mutex
	conf           configuration.Configuration
}

func NewCheckoutHandler(conf configuration.Configuration) *CheckoutHandler {
	return &CheckoutHandler{
		conf: conf,
	}
}

func (ch *CheckoutHandler) BaseFolderPath() string {
	return ch.baseFolderPath
}

func (ch *CheckoutHandler) Repo() *git.Repository {
	return ch.repository
}

func (ch *CheckoutHandler) CleanupFunc() func() {
	return ch.cleanupFunc
}

func (ch *CheckoutHandler) CheckoutBaseBranch(logger *zerolog.Logger, folderConfig *types.FolderConfig) error {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()
	folderPath := folderConfig.FolderPath

	if ch.baseFolderPath != "" && ch.repository != nil && ch.cleanupFunc != nil {
		return nil
	}

	baseBranchName := GetBaseBranchName(ch.conf, folderPath)

	tmpFolderName := fmt.Sprintf(
		"%s_%s",
		NormalizeBranchName(filepath.Base(folderPath)),
		NormalizeBranchName(baseBranchName),
	)
	baseBranchFolderPath, err := os.MkdirTemp("", tmpFolderName)
	logger.Info().Msg("Creating tmp directory for base branch")

	if err != nil {
		logger.Error().Err(err).Msg("Failed to create tmp directory for base branch")
		return err
	}

	repo, err := Clone(logger, folderPath, baseBranchFolderPath, baseBranchName)

	if err != nil {
		logger.Error().Err(err).Msg("Failed to clone base branch")
		return err
	}

	cleanupFunc := func() {
		if baseBranchFolderPath == "" {
			return
		}
		err = os.RemoveAll(baseBranchFolderPath)
		logger.Info().Msg("removing base branch tmp dir " + baseBranchFolderPath)

		if err != nil {
			logger.Error().Err(err).Msg("couldn't remove tmp dir " + baseBranchFolderPath)
		}
	}

	ch.baseFolderPath = baseBranchFolderPath
	ch.repository = repo
	ch.cleanupFunc = cleanupFunc
	return nil
}
