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

package persistence

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

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	CacheFolder   = "snyk"
	SchemaVersion = "v1"
)

var (
	ExpirationInSeconds = 12 * 60 * 60
)

var (
	ErrPathHashDoesntExist                           = errors.New("hashed folder path doesn't exist in cache")
	ErrProductCacheDoesntExist                       = errors.New("product doesn't exist in cache")
	ErrCommitCacheDoesntExist                        = errors.New("commit doesn't exist in cache")
	_                          ScanSnapshotPersister = (*GitPersistenceProvider)(nil)
)

type hashedFolderPath types.FilePath

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

	if len(folderPaths) == 0 {
		return nil
	}

	// force reset in memory cache
	g.cache = make(map[hashedFolderPath]productCommitHashMap)

	for _, folder := range folderPaths {
		cacheDir, err := g.ensureCacheDirExists()

		if err != nil {
			g.logger.Error().Err(err).Msgf("could not determine cache dir for folder path %s", folder)
			return err
		}

		filePaths, err := g.getPersistedFiles(cacheDir)
		if err != nil {
			g.logger.Error().Err(err).Msg("failed to load cached file paths")
			return err
		}

		for _, filePath := range filePaths {
			schemaVersion, hash, commitHash, p, fileParseErr := g.fileSchema(filePath)
			fullPath := filepath.Join(cacheDir, filePath)
			if fileParseErr != nil || g.isExpired(schemaVersion, fullPath) {
				g.logger.Info().Msgf("file %s is expired. attempting to delete", filePath)
				err = g.deleteFile(fullPath)
				if err != nil {
					g.logger.Error().Err(err).Msgf("failed to delete file %s", filePath)
				}
				continue
			}
			g.createOrAppendToCache(hash, commitHash, p)
		}
	}

	g.initialized = true
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

func (g *GitPersistenceProvider) GetPersistedIssueList(folderPath types.FilePath, p product.Product) ([]types.Issue, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	cacheDir := snykCacheDir(g.conf)
	commitHash, err := g.getCommitHashForProduct(folderPath, p)
	if err != nil {
		return nil, err
	}

	if commitHash == "" {
		return nil, errors.New("no commit hash found in cache")
	}

	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	filePath := getLocalFilePath(cacheDir, hash, commitHash, p)
	content, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = g.deleteFromCache(hash, commitHash, p)
			if err != nil {
				g.logger.Error().Err(err).Msg("failed to remove file from cache: " + filePath)
			}
		}
		return nil, err
	}

	var results []types.Issue
	err = json.Unmarshal(content, &results)

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (g *GitPersistenceProvider) Add(folderPath types.FilePath, commitHash string, issueList []types.Issue, p product.Product) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	cacheDir := snykCacheDir(g.conf)
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	shouldPersist := g.shouldPersistOnDisk(hash, commitHash, p)
	if !shouldPersist {
		return nil
	}

	err := g.deleteExistingCachedSnapshot(cacheDir, hash, commitHash, p)
	if err != nil {
		g.logger.Error().Err(err).Msg(string("failed to delete file from disk in " + folderPath))
		return err
	}

	err = g.persistToDisk(cacheDir, hash, commitHash, p, issueList)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to persist cache to disk for commitHash " + commitHash)
		return err
	}

	g.createOrAppendToCache(hash, commitHash, p)

	return nil
}

func (g *GitPersistenceProvider) Exists(folderPath types.FilePath, commitHash string, p product.Product) bool {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	cacheDir := snykCacheDir(g.conf)
	existingCommitHash, err := g.getCommitHashForProduct(folderPath, p)

	if err != nil || existingCommitHash != commitHash || existingCommitHash == "" {
		return false
	}

	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))
	exists := g.snapshotExistsOnDisk(cacheDir, hash, commitHash, p)
	if exists {
		return true
	}

	g.logger.Debug().Msg(string("entry exists in cache but not on disk. Maybe file was deleted? " + folderPath))

	err = g.deleteFromCache(hash, commitHash, p)
	if err != nil {
		g.logger.Error().Err(err).Msg(string("failed to remove file from cache: " + folderPath))
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
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

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
