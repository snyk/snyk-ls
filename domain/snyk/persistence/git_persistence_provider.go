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

// Package persistence implements persistence functionality
package persistence

//go:generate go tool mockgen -destination=mock_persistence/scan_snapshot_persister_mock.go -package=mock_persistence github.com/snyk/snyk-ls/domain/snyk/persistence ScanSnapshotPersister

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:generate go tool github.com/golang/mock/mockgen -source=git_persistence_provider.go -destination mock_persistence/git_persistence_provider_mock.go -package mock_persistence

const (
	CacheFolder   = "snyk"
	SchemaVersion = "v1_1"
)

var (
	ExpirationInSeconds = 12 * 60 * 60
)

var (
	ErrPathHashDoesntExist                           = errors.New("hashed folder path doesn't exist in cache")
	ErrBaselineDoesntExist                           = errors.New("baseline doesn't exist in cache")
	ErrSnapshotCorrupted                             = errors.New("snapshot is corrupted")
	ErrProductCacheDoesntExist                       = errors.New("product doesn't exist in cache")
	ErrCommitCacheDoesntExist                        = errors.New("commit doesn't exist in cache")
	_                          ScanSnapshotPersister = (*GitPersistenceProvider)(nil)
)

type hashedFolderPath string

type ScanSnapshotPersister interface {
	types.ScanSnapshotClearerExister
	Add(folderPath types.FilePath, commitHash string, issueList []types.Issue, p product.Product) error
	GetPersistedIssueList(folderPath types.FilePath, p product.Product) ([]types.Issue, error)
}

type productCommitHashMap map[product.Product]string

type GitPersistenceProvider struct {
	cache       map[hashedFolderPath]productCommitHashMap
	logger      *zerolog.Logger
	mutex       sync.Mutex
	initialized bool
	conf        configuration.Configuration
}

func NewGitPersistenceProvider(logger *zerolog.Logger, conf configuration.Configuration) *GitPersistenceProvider {
	return &GitPersistenceProvider{
		cache:  make(map[hashedFolderPath]productCommitHashMap),
		logger: logger,
		mutex:  sync.Mutex{},
		conf:   conf,
	}
}

// Init Loads persisted files into cache and determines the cache location
func (g *GitPersistenceProvider) Init(folderPaths []types.FilePath) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	logger := g.logger.With().Str("method", "GitPersistenceProvider.Init").Logger()
	logger.Debug().Msgf("called with %d folders", len(folderPaths))

	if len(folderPaths) == 0 {
		return nil
	}

	// force reset in memory cache
	g.cache = make(map[hashedFolderPath]productCommitHashMap)

	for _, folder := range folderPaths {
		cacheDir, err := g.ensureCacheDirExists()

		if err != nil {
			logger.Error().Err(err).Msgf("could not determine cache dir for folder path %s", folder)
			return err
		}

		filePaths, err := g.getPersistedFiles(cacheDir)
		if err != nil {
			logger.Error().Err(err).Msg("failed to load cached file paths")
			return err
		}

		for _, filePath := range filePaths {
			schemaVersion, hash, commitHash, p, fileParseErr := g.fileSchema(filePath)
			fullPath := filepath.Join(cacheDir, filePath)
			if fileParseErr != nil || g.isExpired(schemaVersion, fullPath) {
				logger.Info().Msgf("file %s is expired. attempting to delete", filePath)
				err = g.deleteFile(fullPath)
				if err != nil {
					logger.Error().Err(err).Msgf("failed to delete file %s", filePath)
				}
				continue
			}
			logger.Debug().Msgf("loaded cache entry: hash=%s, commitHash=%s, product=%s", hash, commitHash, p)
			g.createOrAppendToCache(hash, commitHash, p)
		}
	}

	g.initialized = true
	logger.Debug().Msgf("complete, cache has %d entries", len(g.cache))
	return nil
}

func (g *GitPersistenceProvider) Clear(folders []types.FilePath, deleteOnlyExpired bool) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if len(folders) == 0 {
		return
	}
	for _, folderPath := range folders {
		g.logger.Info().Msgf("checking for expired cache for folder %s", folderPath)
		cacheDir := snykCacheDir(g.conf)

		_, err := os.Stat(cacheDir)
		if err != nil {
			continue
		}

		filePaths, err := g.getPersistedFiles(cacheDir)
		if err != nil {
			g.logger.Error().Err(err).Msg("failed to load cached file paths")
		}

		for _, filePath := range filePaths {
			fullPath := filepath.Join(cacheDir, filePath)
			if deleteOnlyExpired {
				err = g.deleteCacheEntryIfExpired(fullPath)
			} else {
				err = g.deleteFile(fullPath)
			}
			if err != nil {
				g.logger.Error().Err(err).Msg("failed to remove file " + filePath)
			}
		}
	}
	if !deleteOnlyExpired {
		g.cache = make(map[hashedFolderPath]productCommitHashMap)
	}
}

func (g *GitPersistenceProvider) ClearFolder(folderPath types.FilePath) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	hash := getHashForFolderPath(folderPath)
	g.logger.Debug().Str("folderPath", string(folderPath)).Str("hash", string(hash)).Msg("clearing in-memory cache for folder")
	delete(g.cache, hash)
}

// findCommitHashOnDisk attempts to find a commit hash on disk when the in-memory cache misses.
// This fixes IDE-1514: GetPersistedIssueList fails when cache is not initialized.
// Returns the commit hash if found, or empty string if not found.
func (g *GitPersistenceProvider) findCommitHashOnDisk(cacheDir string, hash hashedFolderPath, p product.Product, logger zerolog.Logger) string {
	logger.Debug().
		Str("cacheDir", cacheDir).
		Msg("cache miss, attempting fallback to disk lookup")

	persistedFiles, diskErr := g.getPersistedFiles(cacheDir)
	if diskErr != nil {
		logger.Debug().
			Err(diskErr).
			Str("cacheDir", cacheDir).
			Msg("failed to read persisted files from cache directory during fallback")
		return ""
	}

	logger.Debug().
		Int("fileCount", len(persistedFiles)).
		Str("expectedHash", string(hash)).
		Str("expectedProduct", string(p)).
		Msg("scanning disk files for matching cache entry")

	for _, fileName := range persistedFiles {
		commitHash := g.tryMatchCacheFile(cacheDir, fileName, hash, p, logger)
		if commitHash != "" {
			return commitHash
		}
	}

	logger.Debug().
		Int("filesScanned", len(persistedFiles)).
		Str("expectedHash", string(hash)).
		Str("expectedProduct", string(p)).
		Msg("no matching cache file found on disk after scanning all files")
	return ""
}

// tryMatchCacheFile checks if a cache file matches the requested folder path and product.
// Returns the commit hash if it's a valid match, empty string otherwise.
func (g *GitPersistenceProvider) tryMatchCacheFile(cacheDir, fileName string, hash hashedFolderPath, p product.Product, logger zerolog.Logger) string {
	fullPath := filepath.Join(cacheDir, fileName)
	schemaVersion, fileHash, fileCommitHash, fileProduct, parseErr := g.fileSchema(fullPath)
	if parseErr != nil {
		logger.Debug().
			Err(parseErr).
			Str("filePath", fullPath).
			Msg("failed to parse cache file schema, skipping")
		return ""
	}

	if fileHash != hash {
		logger.Debug().
			Str("filePath", fullPath).
			Str("fileHash", string(fileHash)).
			Str("expectedHash", string(hash)).
			Msg("file hash mismatch, skipping")
		return ""
	}

	if fileProduct != p {
		logger.Debug().
			Str("filePath", fullPath).
			Str("fileProduct", string(fileProduct)).
			Str("expectedProduct", string(p)).
			Msg("file product mismatch, skipping")
		return ""
	}

	if g.isExpired(schemaVersion, fullPath) {
		logger.Debug().
			Str("filePath", fullPath).
			Str("commitHash", fileCommitHash).
			Msg("found matching file on disk but it is expired, skipping")
		return ""
	}

	// Found a valid match!
	g.createOrAppendToCache(hash, fileCommitHash, p)
	logger.Debug().
		Str("commitHash", fileCommitHash).
		Str("filePath", fullPath).
		Msg("found commit hash on disk, updated cache")
	return fileCommitHash
}

func (g *GitPersistenceProvider) GetPersistedIssueList(folderPath types.FilePath, p product.Product) ([]types.Issue, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	logger := g.logger.With().
		Str("method", "GitPersistenceProvider.GetPersistedIssueList").
		Str("folderPath", string(folderPath)).
		Str("product", string(p)).
		Logger()
	logger.Debug().Msgf("getting persisted issue list")

	cacheDir := snykCacheDir(g.conf)
	hash := getHashForFolderPath(folderPath)
	commitHash, err := g.getCommitHashForProduct(folderPath, p)
	logger.Debug().Msgf("commitHash=%s, err=%v", commitHash, err)

	if err != nil {
		commitHash = g.findCommitHashOnDisk(cacheDir, hash, p, logger)
		if commitHash == "" {
			logger.Debug().
				Err(err).
				Str("cacheDir", cacheDir).
				Str("folderPathHash", string(hash)).
				Msg("fallback to disk failed, returning error")
			return nil, ErrBaselineDoesntExist
		}
	}

	if commitHash == "" {
		return nil, ErrBaselineDoesntExist
	}
	filePath := getLocalFilePath(cacheDir, hash, commitHash, p)
	content, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn().
				Str("hash", string(hash)).
				Str("filePath", filePath).
				Str("commitHash", commitHash).
				Msg("cache file not found on disk, but was in the in-memory cache list, removing from said list")
			err = g.deleteFromCache(hash, commitHash, p)
			if err != nil {
				logger.Error().Err(err).Msg("failed to remove file from cache: " + filePath)
			}
			return nil, ErrSnapshotCorrupted
		}
		return nil, err
	}

	var snykIssues []snyk.Issue
	err = json.Unmarshal(content, &snykIssues)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to unmarshal snapshot, deleting")
		err = g.deleteFromCache(hash, commitHash, p)
		if err != nil {
			logger.Error().Err(err).Msg("failed to remove file from cache: " + filePath)
		}

		deletionErr := os.Remove(filePath)
		if deletionErr != nil {
			logger.Error().Err(deletionErr).Msg("failed to remove file from disk: " + filePath)
		}
		return nil, ErrSnapshotCorrupted
	}

	var results []types.Issue
	for i := range snykIssues {
		results = append(results, &snykIssues[i])
	}
	logger.Debug().Msgf("returning %d issues", len(results))
	return results, nil
}

func (g *GitPersistenceProvider) Add(folderPath types.FilePath, commitHash string, issueList []types.Issue, p product.Product) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	logger := g.logger.With().
		Str("method", "GitPersistenceProvider.Add").
		Str("folderPath", string(folderPath)).
		Str("product", string(p)).
		Str("commitHash", commitHash).
		Logger()
	logger.Debug().
		Int("issueCount", len(issueList)).
		Msg("persisting baseline scan results")

	cacheDir := snykCacheDir(g.conf)
	hash := getHashForFolderPath(folderPath)

	shouldPersist := g.shouldPersistOnDisk(hash, commitHash, p)
	if !shouldPersist {
		return nil
	}

	err := g.deleteExistingCachedSnapshot(cacheDir, hash, commitHash, p)
	if err != nil {
		logger.Error().Err(err).Msg(string("failed to delete file from disk"))
		return err
	}

	err = g.persistToDisk(cacheDir, hash, commitHash, p, issueList)
	if err != nil {
		logger.Error().Err(err).Msg("failed to persist cache to disk")
		return err
	}

	g.createOrAppendToCache(hash, commitHash, p)

	return nil
}

func (g *GitPersistenceProvider) Exists(folderPath types.FilePath, commitHash string, p product.Product) bool {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	logger := g.logger.With().
		Str("method", "GitPersistenceProvider.Exists").
		Str("folderPath", string(folderPath)).
		Str("product", string(p)).
		Str("commitHash", commitHash).
		Logger()
	logger.Debug().Msgf("checking for existing snapshot")

	cacheDir := snykCacheDir(g.conf)
	existingCommitHash, err := g.getCommitHashForProduct(folderPath, p)

	logger.Debug().Msgf("existingCommitHash=%s, err=%v", existingCommitHash, err)

	if err != nil || existingCommitHash != commitHash || existingCommitHash == "" {
		logger.Debug().Msg("returning FALSE")
		return false
	}

	hash := getHashForFolderPath(folderPath)
	exists := g.snapshotExistsOnDisk(cacheDir, hash, commitHash, p)
	logger.Debug().Msgf("snapshotExistsOnDisk=%t", exists)
	if exists {
		logger.Debug().Msg("returning TRUE")
		return true
	}

	logger.Debug().Msg(string("entry exists in cache but not on disk. Maybe file was deleted? " + folderPath))

	err = g.deleteFromCache(hash, commitHash, p)
	if err != nil {
		logger.Error().Err(err).Msg(string("failed to remove file from cache: " + folderPath))
	}
	return false
}

func (g *GitPersistenceProvider) fileSchema(fullPath string) (string, hashedFolderPath, string, product.Product, error) {
	// file name structure is schemaVersion.hashedFolderPath.commitHash.productName.json
	s := strings.Split(filepath.Base(fullPath), ".")
	if len(s) != 5 {
		return "", "", "", "", fmt.Errorf("failed to parse file name %s", fullPath)
	}
	schemaVersion := s[0]
	hash := hashedFolderPath(s[1])
	commitHash := s[2]
	p := product.ToProduct(s[3])
	return schemaVersion, hash, commitHash, p, nil
}

func (g *GitPersistenceProvider) deleteCacheEntryIfExpired(fullPath string) error {
	schemaVersion, hash, commitHash, p, _ := g.fileSchema(fullPath)
	isExpired := g.isExpired(schemaVersion, fullPath)
	if isExpired {
		g.logger.Debug().Msgf("deleting cached scan file %s", fullPath)
		return g.deleteFromDiskAndCache(fullPath, hash, commitHash, p)
	}

	return nil
}

func (g *GitPersistenceProvider) deleteFromDiskAndCache(fullPath string, hash hashedFolderPath, commitHash string, p product.Product) error {
	err := g.deleteFile(fullPath)
	if err != nil {
		g.logger.Debug().Err(err).Msg("could not remove cached file from disk: " + fullPath)
	}
	err = g.deleteFromCache(hash, commitHash, p)
	if err != nil {
		g.logger.Debug().Err(err).Msg("failed to remove file from cache: " + fullPath)
	}
	return err
}

func (g *GitPersistenceProvider) deleteFromCache(hash hashedFolderPath, commitHash string, p product.Product) error {
	productCommitHashCache, exists := g.cache[hash]
	if !exists {
		return ErrPathHashDoesntExist
	}

	currentCommitHash, productCacheExists := productCommitHashCache[p]
	if !productCacheExists {
		return ErrProductCacheDoesntExist
	}

	if currentCommitHash != commitHash {
		return ErrCommitCacheDoesntExist
	}

	delete(g.cache[hash], p)

	return nil
}

func (g *GitPersistenceProvider) getCommitHashForProduct(folderPath types.FilePath, p product.Product) (commitHash string, err error) {
	hash := getHashForFolderPath(folderPath)

	pchMap, ok := g.cache[hash]
	if !ok {
		return "", ErrPathHashDoesntExist
	}
	commitHash = pchMap[p]
	return commitHash, nil
}

func (g *GitPersistenceProvider) shouldPersistOnDisk(folderPathHash hashedFolderPath, commitHash string, p product.Product) bool {
	pchm, pchmExists := g.cache[folderPathHash]
	if !pchmExists {
		return true
	}

	ch, commitHashExists := pchm[p]
	if !commitHashExists {
		return true
	}

	if ch == commitHash {
		return false
	}

	return true
}

func (g *GitPersistenceProvider) deleteExistingCachedSnapshot(cacheDir string, folderPathHash hashedFolderPath, commitHash string, p product.Product) error {
	pchm, pchmExists := g.cache[folderPathHash]
	if !pchmExists {
		return nil
	}

	cachedCommitHash, commitHashExists := pchm[p]
	if !commitHashExists {
		return nil
	}

	if cachedCommitHash == commitHash {
		return nil
	}

	filePath := getLocalFilePath(cacheDir, folderPathHash, cachedCommitHash, p)
	err := g.deleteFile(filePath)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to remove persisted scan file for product " + p.ToProductCodename())
	}

	err = g.deleteFromCache(folderPathHash, cachedCommitHash, p)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to delete cached scan for product: " + p.ToProductCodename())
		return err
	}

	return nil
}

func (g *GitPersistenceProvider) createOrAppendToCache(pathHash hashedFolderPath, commitHash string, product product.Product) {
	pchm, exists := g.cache[pathHash]
	if !exists {
		pchm = make(productCommitHashMap)
	}
	pchm[product] = commitHash
	g.cache[pathHash] = pchm
}
