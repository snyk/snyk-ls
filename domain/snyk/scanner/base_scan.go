/*
 * © 2025 Snyk Limited
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

package scanner

import (
	"context"
	"errors"

	"github.com/gosimple/hashdir"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/vcs"
)

func (sc *DelegatingConcurrentScanner) scanBaseBranch(ctx context.Context, s snyk.ProductScanner, folderConfig *types.FolderConfig, checkoutHandler *vcs.CheckoutHandler) error {
	logger := sc.c.Logger().With().Str("method", "scanBaseBranch").Logger()
	if folderConfig == nil {
		return errors.New("folder config is required")
	}

	folderPath := folderConfig.FolderPath
	baseFolderPath := folderConfig.ReferenceFolderPath
	persistHash, err := sc.getPersistHash(folderConfig)
	if err != nil {
		return err
	}

	// we only scan if needed
	snapshotExists := sc.scanPersister.Exists(folderPath, persistHash, s.Product())
	if snapshotExists {
		return nil
	}

	// only clone if reference folder not given
	if baseFolderPath == "" {
		err = sc.cloneForBaseScan(folderConfig, checkoutHandler)
		if err != nil {
			return err
		}
		baseFolderPath = checkoutHandler.BaseFolderPath()
	}

	// prepare the scan directory with the pre-scan command
	err = sc.executePreScanCommand(ctx, sc.c, s.Product(), folderConfig, baseFolderPath, false)
	if err != nil {
		logger.Err(err).Str("folderPath", folderPath).Str("baseFolderPath", baseFolderPath).Send()
		return err
	}

	// scan
	var results []snyk.Issue
	if s.Product() == product.ProductCode {
		results, err = s.Scan(ctx, "", baseFolderPath)
	} else {
		results, err = s.Scan(ctx, baseFolderPath, "")
	}
	if err != nil {
		logger.Error().Err(err).Msgf("skipping base scan persistence in %s %v", folderPath, err)
		return err
	}

	sc.persistScanResults(folderConfig, results, s)

	return nil
}

func (sc *DelegatingConcurrentScanner) persistScanResults(
	folderConfig *types.FolderConfig,
	results []snyk.Issue,
	s snyk.ProductScanner,
) {
	logger := sc.c.Logger().With().Str("method", "persistScanResults").Logger()
	folderPath := folderConfig.FolderPath
	defer logger.Info().Msgf("finished persisting issues for %s", folderPath)

	persistHash, err := sc.getPersistHash(folderConfig)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to persist issues for %s", folderPath)
		return
	}

	err = sc.scanPersister.Add(folderPath, persistHash, results, s.Product())
	if err != nil {
		logger.Error().Err(err).Msg("could not persist issue list for folder: " + folderPath)
	}
}

func (sc *DelegatingConcurrentScanner) getPersistHash(folderConfig *types.FolderConfig) (string, error) {
	logger := sc.c.Logger().With().Str("method", "getPersistHash").Logger()
	var persistHash string
	var err error
	if folderConfig.ReferenceFolderPath != "" {
		// this is not a performance problem
		// jdk repository hashing (2.1 GB with lots of files) takes 5.9s on a Mac M3 Pro
		persistHash, err = hashdir.Make(folderConfig.ReferenceFolderPath, "sha256")
	} else {
		persistHash, err = vcs.HeadRefHashForBranch(&logger, folderConfig.FolderPath, folderConfig.BaseBranch)
	}
	return persistHash, err
}

func (sc *DelegatingConcurrentScanner) cloneForBaseScan(folderConfig *types.FolderConfig, checkoutHandler *vcs.CheckoutHandler) error {
	logger := sc.c.Logger().With().Str("method", "cloneForBaseScan").Logger()
	folderPath := folderConfig.FolderPath

	err := checkoutHandler.CheckoutBaseBranch(&logger, folderConfig)
	if err != nil {
		logger.Error().Err(err).Msgf("couldn't check out base branch for folderPath %s", folderPath)
		return err
	}
	return nil
}
