/*
 * © 2025-2026 Snyk Limited
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

// Package scanner defines the scanner interface and common functionality used in all scanners
package scanner

import (
	"context"
	"errors"

	"github.com/gosimple/hashdir"

	"github.com/snyk/snyk-ls/infrastructure/utils"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/vcs"
)

var ErrMissingDeltaReference = errors.New(utils.ErrNoReferenceBranch)

func (sc *DelegatingConcurrentScanner) scanBaseBranch(ctx context.Context, s types.ProductScanner, folderConfig *types.FolderConfig, checkoutHandler *vcs.CheckoutHandler) error {
	logger := sc.c.Logger().With().
		Str("method", "scanBaseBranch").
		Str("product", string(s.Product())).
		Logger()

	if folderConfig == nil {
		return errors.New("folder config is required")
	}

	if err := types.ValidatePathStrict(folderConfig.FolderPath); err != nil {
		logger.Error().Err(err).Str("path", string(folderConfig.FolderPath)).Msg("invalid folder path")
		return err
	}

	if folderConfig.ReferenceFolderPath != "" {
		if err := types.ValidatePathLenient(folderConfig.ReferenceFolderPath); err != nil {
			logger.Error().Err(err).Str("referencePath", string(folderConfig.ReferenceFolderPath)).Msg("invalid reference folder path")
			return err
		}
	}

	folderPath := folderConfig.FolderPath
	baseFolderPath := folderConfig.ReferenceFolderPath

	// Enrich logger with folderPath now that we have it
	logger = logger.With().Str("folderPath", string(folderPath)).Logger()

	logger.Debug().Msg("scanBaseBranch: starting reference/base branch scan")
	persistHash, err := sc.getPersistHash(folderConfig)
	if err != nil {
		return err
	}

	// we only scan if needed
	snapshotExists := sc.scanPersister.Exists(folderPath, persistHash, s.Product())
	if snapshotExists {
		logger.Debug().Msg("scanBaseBranch: snapshot exists, skipping scan")
		return nil
	}

	// only clone if reference folder not given
	if baseFolderPath == "" {
		logger.Debug().Msg("scanBaseBranch: cloning base branch for scan")
		err = sc.cloneForBaseScan(folderConfig, checkoutHandler)
		if err != nil {
			return err
		}
		baseFolderPath = checkoutHandler.BaseFolderPath()
	} else {
		logger.Debug().
			Str("referenceFolderPath", string(baseFolderPath)).
			Msg("scanBaseBranch: using provided reference folder")
	}

	// Now that we know baseFolderPath, enrich the logger with it
	logger = logger.With().Str("baseFolderPath", string(baseFolderPath)).Logger()

	// prepare the scan directory with the pre-scan command
	err = sc.executePreScanCommand(ctx, sc.c, s.Product(), folderConfig, baseFolderPath, false)
	if err != nil {
		logger.Err(err).Send()
		return err
	}

	// scan
	var results []types.Issue
	logger.Debug().Msg("scanBaseBranch: scanning reference folder")
	// All scanners use workspaceFolderConfig.FolderPath as the scan root.
	// For a base branch scan, this must be the temporary directory of the base branch checkout.
	// We clone the folderConfig to avoid modifying the original and to pass the correct scan root.
	baseScanConfig := *folderConfig
	baseScanConfig.FolderPath = baseFolderPath
	// Pass baseFolderPath as pathToScan as we want to perform a full workspace scan
	results, err = s.Scan(ctx, baseFolderPath, &baseScanConfig)
	if err != nil {
		logger.Error().Err(err).Msgf("skipping base scan persistence in %s %v", folderPath, err)
		return err
	}

	sc.persistScanResults(folderConfig, results, s)

	return nil
}

func (sc *DelegatingConcurrentScanner) persistScanResults(
	folderConfig *types.FolderConfig,
	results []types.Issue,
	s types.ProductScanner,
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
		logger.Error().Err(err).Msg(string("could not persist issue list for folder: " + folderPath))
	}
}

func (sc *DelegatingConcurrentScanner) getPersistHash(folderConfig *types.FolderConfig) (string, error) {
	logger := sc.c.Logger().With().Str("method", "getPersistHash").Logger()
	var persistHash string
	var err error
	if folderConfig.ReferenceFolderPath != "" {
		// this is not a performance problem
		// jdk repository hashing (2.1 GB with lots of files) takes 5.9s on a Mac M3 Pro
		persistHash, err = hashdir.Make(string(folderConfig.ReferenceFolderPath), "sha256")
		if err == nil {
			logger.Debug().
				Str("referenceFolderPath", string(folderConfig.ReferenceFolderPath)).
				Str("persistHash", persistHash).
				Msg("using directory hash as baseline identifier")
		}
	} else if folderConfig.BaseBranch != "" {
		persistHash, err = vcs.HeadRefHashForBranch(&logger, folderConfig.FolderPath, folderConfig.BaseBranch)
		if err == nil {
			logger.Debug().
				Str("baseBranch", folderConfig.BaseBranch).
				Str("persistHash", persistHash).
				Msg("using commit hash as baseline identifier")
		}
	} else {
		return "", ErrMissingDeltaReference
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
