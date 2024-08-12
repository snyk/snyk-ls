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
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/util"
	"github.com/snyk/snyk-ls/internal/vcs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	CacheFolder   = "snyk"
	SchemaVersion = "v1"
)

var (
	ErrPathHashDoesntExist                       = errors.New("hashed folder path doesn't exist in cache")
	ErrProductDoesntExist                        = errors.New("product doesn't exist in cache")
	ErrCommitDoesntExist                         = errors.New("commit doesn't exist in cache")
	_                      ScanSnapshotPersister = (*GitPersistenceProvider)(nil)
)

type hashedFolderPath string

type ScanSnapshotPersister interface {
	Clear(folderPath string)
	ClearForProduct(folderPath string, commitHash string, p product.Product) error
	Add(folderPath, commitHash string, issueList []snyk.Issue, p product.Product) error
	GetPersistedIssueList(folderPath string, p product.Product) ([]snyk.Issue, error)
	Exists(folderPath, commitHash string, p product.Product) bool
}

type productCommitHashMap map[product.Product]string

type GitPersistenceProvider struct {
	cache       map[hashedFolderPath]productCommitHashMap
	logger      *zerolog.Logger
	mutex       sync.Mutex
	initialized bool
}

func NewGitPersistenceProvider(logger *zerolog.Logger) *GitPersistenceProvider {
	return &GitPersistenceProvider{
		cache:  make(map[hashedFolderPath]productCommitHashMap),
		logger: logger,
		mutex:  sync.Mutex{},
	}
}

// Loads persisted files into cache and determines the cache location
// init can't be triggered only once in the beginning of LS init. Since it needs a folder path.
// Current Solution is to attempt to trigger it with every call and early exit if it was called once.
func (g *GitPersistenceProvider) init(folderPath string) (string, error) {
	cacheDir, err := g.ensureCacheDirExists(folderPath)

	if err != nil {
		g.logger.Error().Err(err).Msg("could not determine cache dir")
		return "", err
	}

	if g.initialized {
		return cacheDir, nil
	}

	filePaths, err := g.getPersistedFiles(cacheDir)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to load cached file paths")
		return "", err
	}
	for _, filePath := range filePaths {
		// file name structure is schema.hashedFolderPath.commitHash.productName.json
		s := strings.Split(filePath, ".")
		hash := hashedFolderPath(s[1])
		commitHash := s[2]
		p := product.ToProduct(s[3])
		g.createOrAppendToCache(hash, commitHash, p)
	}

	g.initialized = true
	return cacheDir, nil
}

func (g *GitPersistenceProvider) Clear(folderPath string) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	cacheDir, err := g.init(folderPath)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to initialize git persistence provider")
	}

	filePaths, err := g.getPersistedFiles(cacheDir)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to load cached file paths")
	}

	for _, filePath := range filePaths {
		fullPath := filepath.Join(cacheDir, filePath)
		err = g.deleteFile(fullPath)
		if err != nil {
			g.logger.Error().Err(err).Msg("failed to remove file " + filePath)
		}
	}
	g.cache = make(map[hashedFolderPath]productCommitHashMap)
}

func (g *GitPersistenceProvider) ClearForProduct(folderPath, commitHash string, p product.Product) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	cacheDir, err := g.init(folderPath)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to initialize git persistence provider")
	}

	hash := hashedFolderPath(util.Sha256First16Hash(folderPath))

	err = g.deleteFromCache(hash, commitHash, p)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to delete cached scan for product: " + p.ToProductCodename() + " for folder: " + folderPath)
		return err
	}

	filePath := getLocalFilePath(cacheDir, hash, commitHash, p)
	err = g.deleteFile(filePath)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to remove file: " + folderPath)
	}

	return err
}

func (g *GitPersistenceProvider) GetPersistedIssueList(folderPath string, p product.Product) ([]snyk.Issue, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	cacheDir, err := g.init(folderPath)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to initialize git persistence provider")
	}

	commitHash, err := g.getCommitHashForProduct(folderPath, p)
	if commitHash == "" || err != nil {
		return nil, err
	}

	hash := hashedFolderPath(util.Sha256First16Hash(folderPath))

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

	var results []snyk.Issue
	err = json.Unmarshal(content, &results)

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (g *GitPersistenceProvider) Add(folderPath, commitHash string, issueList []snyk.Issue, p product.Product) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	cacheDir, err := g.init(folderPath)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to initialize git persistence provider")
	}

	hash := hashedFolderPath(util.Sha256First16Hash(folderPath))

	shouldPersist := g.shouldPersistOnDisk(hash, commitHash, p)
	if !shouldPersist {
		return nil
	}

	err = g.deleteExistingCachedSnapshot(cacheDir, hash, commitHash, p)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to delete file from disk in " + folderPath)
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

func (g *GitPersistenceProvider) Exists(folderPath, commitHash string, p product.Product) bool {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	cacheDir, err := g.init(folderPath)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to initialize git persistence provider")
	}

	existingCommitHash, err := g.getCommitHashForProduct(folderPath, p)

	if err != nil || existingCommitHash != commitHash || existingCommitHash == "" {
		return false
	}

	hash := hashedFolderPath(util.Sha256First16Hash(folderPath))
	exists := g.snapshotExistsOnDisk(cacheDir, hash, commitHash, p)
	if exists {
		return true
	}

	g.logger.Debug().Msg("entry exists in cache but not on disk. Maybe file was deleted? " + folderPath)

	err = g.deleteFromCache(hash, commitHash, p)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to remove file from cache: " + folderPath)
	}
	return false
}

func (g *GitPersistenceProvider) deleteFile(fullPath string) error {
	g.logger.Debug().Msg("deleting cached scan file " + fullPath)
	err := os.Remove(fullPath)
	if err != nil {
		return err
	}
	return nil
}

func (g *GitPersistenceProvider) deleteFromCache(hash hashedFolderPath, commitHash string, p product.Product) error {
	pchm, exists := g.cache[hash]
	if !exists {
		return ErrPathHashDoesntExist
	}

	currentCommitHash, pchExists := pchm[p]
	if !pchExists {
		return ErrProductDoesntExist
	}

	if currentCommitHash != commitHash {
		return ErrCommitDoesntExist
	}

	delete(g.cache[hash], p)

	return nil
}

func (g *GitPersistenceProvider) snapshotExistsOnDisk(cacheDir string, hash hashedFolderPath, commitHash string, p product.Product) bool {
	filePath := getLocalFilePath(cacheDir, hash, commitHash, p)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	return true
}

func (g *GitPersistenceProvider) getCommitHashForProduct(folderPath string, p product.Product) (commitHash string, err error) {
	hash := hashedFolderPath(util.Sha256First16Hash(folderPath))

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

func (g *GitPersistenceProvider) getPersistedFiles(cacheDir string) (persistedFiles []string, err error) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return persistedFiles, err
	}

	for _, entry := range entries {
		fileName := entry.Name()
		if !strings.HasSuffix(fileName, ".json") {
			continue
		}
		s := strings.Split(fileName, ".")
		if len(s) == 5 {
			persistedFiles = append(persistedFiles, fileName)
		}
	}
	return persistedFiles, nil
}

func (g *GitPersistenceProvider) persistToDisk(cacheDir string, folderHashedPath hashedFolderPath, commitHash string, p product.Product, inputToCache []snyk.Issue) error {
	filePath := getLocalFilePath(cacheDir, folderHashedPath, commitHash, p)
	data, err := json.Marshal(inputToCache)
	if err != nil {
		return err
	}
	g.logger.Debug().Msg("persisting scan results in file " + filePath)
	return os.WriteFile(filePath, data, 0644)
}

func (g *GitPersistenceProvider) ensureCacheDirExists(folderPath string) (string, error) {
	g.logger.Info().Msg("attempting to determine .git folder path")
	gitFolder, err := vcs.GitRepoFolderPath(g.logger, folderPath)
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(gitFolder, CacheFolder)

	if _, err = os.Stat(cacheDir); os.IsNotExist(err) {
		err = os.Mkdir(cacheDir, 0700)
		if err != nil {
			return "", err
		}
	}
	return cacheDir, nil
}

func getLocalFilePath(cacheDir string, folderPathHash hashedFolderPath, commitHash string, p product.Product) string {
	productName := p.ToProductCodename()
	return filepath.Join(cacheDir, fmt.Sprintf("%s.%s.%s.%s.json", SchemaVersion, folderPathHash, commitHash, productName))
}
