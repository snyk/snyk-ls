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

// Package vcs implements VCS integration
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
	baseFolderPath types.FilePath
	repository     *git.Repository
	cleanupFunc    func()
	attempted      bool
	attemptErr     error
	mutex          sync.Mutex
	conf           configuration.Configuration
}

func NewCheckoutHandler(conf configuration.Configuration) *CheckoutHandler {
	return &CheckoutHandler{
		conf: conf,
	}
}

func (ch *CheckoutHandler) BaseFolderPath() types.FilePath {
	return ch.baseFolderPath
}

// Repo returns the base branch clone. Its worktree is written directly rather
// than checked out, so no index describes it: every file reads as both
// deleted-from-index and untracked, and `git ls-files` is empty. On the
// detached-HEAD fallback the index is worse than empty - it is the source
// repository's, copied along with .git and never reset.
func (ch *CheckoutHandler) Repo() *git.Repository {
	return ch.repository
}

func (ch *CheckoutHandler) CleanupFunc() func() {
	return ch.cleanupFunc
}

func (ch *CheckoutHandler) CheckoutBaseBranch(logger *zerolog.Logger, folderConfig *types.FolderConfig) error {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	// Memoize the attempt, not just success. This handler is per scan and every
	// product scanner calls it, so a failure would otherwise be repeated N times,
	// each retry now also paying for its own cleanup inside this lock.
	if ch.attempted {
		return ch.attemptErr
	}
	ch.attempted = true
	ch.attemptErr = ch.checkoutBaseBranch(logger, folderConfig)
	return ch.attemptErr
}

func (ch *CheckoutHandler) checkoutBaseBranch(logger *zerolog.Logger, folderConfig *types.FolderConfig) error {
	folderPath := folderConfig.FolderPath

	baseBranchName := GetBaseBranchName(ch.conf, folderPath, logger)

	tmpFolderName := fmt.Sprintf(
		"%s_%s",
		NormalizeBranchName(filepath.Base(string(folderPath))),
		NormalizeBranchName(baseBranchName),
	)
	logger.Info().Str("tmpFolderName", tmpFolderName).Msg("Creating tmp directory for base branch")
	baseBranchFolderPath, err := os.MkdirTemp("", tmpFolderName)
	logger.Info().Str("baseBranchFolderPath", baseBranchFolderPath).Msg("Created tmp directory for base branch")

	if err != nil {
		logger.Error().Err(err).Msg("Failed to create tmp directory for base branch")
		return err
	}

	cleanupFunc := func() {
		if baseBranchFolderPath == "" {
			return
		}
		logger.Info().Msg("removing base branch tmp dir " + baseBranchFolderPath)
		// Through OSPath because that is how the clone's files were created; a
		// reserved device name is not reachable by any other spelling.
		if removeErr := os.RemoveAll(OSPath(baseBranchFolderPath)); removeErr != nil {
			logger.Error().Err(removeErr).Msg("couldn't remove tmp dir " + baseBranchFolderPath)
		}
	}

	repo, err := Clone(logger, folderPath, types.FilePath(baseBranchFolderPath), baseBranchName)

	if err != nil {
		logger.Error().Err(err).Msg("Failed to clone base branch")
		// A failed clone can still have written a partial worktree, and every
		// product scanner retries this, so each attempt would leak its own copy.
		cleanupFunc()
		return err
	}

	ch.baseFolderPath = types.FilePath(baseBranchFolderPath)
	ch.repository = repo
	ch.cleanupFunc = cleanupFunc
	return nil
}
