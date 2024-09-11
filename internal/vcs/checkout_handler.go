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
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
)

type CheckoutHandler struct {
	baseFolderPath string
	repository     *git.Repository
	cleanupFunc    func()
	mutex          sync.Mutex
}

func NewCheckoutHandler() *CheckoutHandler {
	return &CheckoutHandler{}
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

func (ch *CheckoutHandler) CheckoutBaseBranch(logger *zerolog.Logger, folderPath string) error {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	if ch.baseFolderPath != "" && ch.repository != nil && ch.cleanupFunc != nil {
		return nil
	}

	baseBranchName := GetBaseBranchName(folderPath)

	tmpFolderName := fmt.Sprintf("snyk_delta_%s", NormalizeBranchName(baseBranchName))
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
