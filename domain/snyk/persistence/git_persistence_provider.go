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
	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/spaolacci/murmur3"
	"github.com/spf13/afero"
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
	_                    ScanSnapshotPersister = (*GitPersistenceProvider)(nil)
	currentCacheProvider *GitPersistenceProvider
)

type ScanSnapshotPersister interface {
	Clear()
	ClearForProduct(folderPath string, p product.Product)
	Init()
	Add(folderPath, commitHash string, issueList []snyk.Issue, p product.Product) error
	GetPersistedIssueList(folderPath string, p product.Product) ([]snyk.Issue, error)
	SnapshotExists(folderPath, commitHash string, p product.Product) bool
}

type productCommitHashMap map[product.Product]string

type GitPersistenceProvider struct {
	cache  map[string]productCommitHashMap
	logger *zerolog.Logger
	mutex  sync.Mutex
	fs     afero.Fs
}

func NewGitPersistenceProvider(logger *zerolog.Logger, fs afero.Fs) *GitPersistenceProvider {
	currentCacheProvider = &GitPersistenceProvider{
		cache:  make(map[string]productCommitHashMap),
		logger: logger,
		mutex:  sync.Mutex{},
		fs:     fs,
	}
	return currentCacheProvider
}

func CurrentGitCache() *GitPersistenceProvider {
	return currentCacheProvider
}

func (gpp *GitPersistenceProvider) Clear() {
	gpp.mutex.Lock()
	defer gpp.mutex.Unlock()

	filePaths := gpp.getPersistedCachedFilePaths()
	for _, filePath := range filePaths {
		gpp.deleteAllPersistedFilesForPath(filePath)
	}
	gpp.cache = make(map[string]productCommitHashMap)
}

func (gpp *GitPersistenceProvider) deleteAllPersistedFilesForPath(filePath string) {
	filePathHash, err := hashPath(filePath)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed hash path " + filePath)
		return
	}
	if pchm, exists := gpp.cache[filePathHash]; exists {
		for p, commitHash := range pchm {
			err = gpp.deletePersistedFile(filePathHash, commitHash, p)
			if err != nil {
				gpp.logger.Error().Err(err).Msg("failed remove file " + filePath)
			}
		}
	}
}

func (gpp *GitPersistenceProvider) ClearForProduct(path string, p product.Product) {
	gpp.mutex.Lock()
	defer gpp.mutex.Unlock()
	hash, err := hashPath(path)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to hash path " + path)
	}
	pchm, exists := gpp.cache[hash]
	if !exists {
		return
	}

	commitHash, pchExists := pchm[p]
	if !pchExists {
		return
	}
	err = gpp.deletePersistedFile(hash, commitHash, p)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to remove file: " + path)
	}
	delete(gpp.cache, hash)
}

func (gpp *GitPersistenceProvider) Init() {
	gpp.mutex.Lock()
	defer gpp.mutex.Unlock()

	filePaths := gpp.getPersistedCachedFilePaths()
	for _, filePath := range filePaths {
		s := strings.Split(filePath, ".")
		p := product.ToProduct(s[3])
		gpp.createOrAppendToCache(s[1], s[2], p)
	}
}

func (gpp *GitPersistenceProvider) GetPersistedIssueList(folderPath string, p product.Product) ([]snyk.Issue, error) {
	commitHash, err := gpp.getProductCommitHash(folderPath, p)
	if commitHash == "" || err != nil {
		return nil, err
	}

	hashedFolderPath, err := hashPath(folderPath)
	if err != nil {
		return nil, err
	}
	filePath := getLocalFilePath(hashedFolderPath, commitHash, p)
	content, err := afero.ReadFile(gpp.fs, filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			delete(gpp.cache, hashedFolderPath)
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

func (gpp *GitPersistenceProvider) SnapshotExists(folderPath, commitHash string, p product.Product) bool {
	existingCommitHash, err := gpp.getProductCommitHash(folderPath, p)
	if err != nil || existingCommitHash != commitHash {
		return false
	}

	hashedFolderPath, err := hashPath(folderPath)
	if err != nil {
		return false
	}

	filePath := getLocalFilePath(hashedFolderPath, commitHash, p)
	if _, err = gpp.fs.Stat(filePath); os.IsNotExist(err) {
		return false
	}

	return true
}

func (gpp *GitPersistenceProvider) getProductCommitHash(folderPath string, p product.Product) (commitHash string, err error) {
	gpp.mutex.Lock()
	defer gpp.mutex.Unlock()

	hashedFolderPath, err := hashPath(folderPath)
	if err != nil {
		return "", err
	}
	pchMap, ok := gpp.cache[hashedFolderPath]
	if !ok {
		return "", nil
	}
	commitHash = pchMap[p]
	return commitHash, nil
}

func (gpp *GitPersistenceProvider) Add(folderPath, commitHash string, issueList []snyk.Issue, p product.Product) error {
	gpp.mutex.Lock()
	defer gpp.mutex.Unlock()

	err := gpp.ensureCacheDirExists()
	if err != nil {
		gpp.logger.Error().Err(err).Msg("could not create cache dir")
		return err
	}
	hash, err := hashPath(folderPath)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("could not hash path" + folderPath)
		return err
	}

	shouldPersist := gpp.checkAndRemoveExistingFile(hash, commitHash, p)
	if !shouldPersist {
		return nil
	}
	err = gpp.persistToDisk(hash, commitHash, p, issueList)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to persist cache to disk for commitHash " + commitHash)
		return err
	}

	gpp.createOrAppendToCache(hash, commitHash, p)

	return nil
}

func (gpp *GitPersistenceProvider) checkAndRemoveExistingFile(folderPathHash string, commitHash string, p product.Product) bool {
	pchm, pchmExists := gpp.cache[folderPathHash]
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

	filePath := getLocalFilePath(folderPathHash, ch, p)
	err := gpp.fs.Remove(filePath)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to remove file " + filePath)
		return true
	}
	delete(gpp.cache, folderPathHash)

	return true
}

func (gpp *GitPersistenceProvider) createOrAppendToCache(pathHash string, commitHash string, product product.Product) {
	pchm, exists := gpp.cache[pathHash]
	if !exists {
		pchm = make(productCommitHashMap)
	}
	pchm[product] = commitHash
	gpp.cache[pathHash] = pchm
}

func (gpp *GitPersistenceProvider) getPersistedCachedFilePaths() (cachedFilePaths []string) {
	entries, err := afero.ReadDir(gpp.fs, filepath.Join(xdg.CacheHome, CacheFolder))
	if err != nil {
		return cachedFilePaths
	}

	for _, entry := range entries {
		fileName := entry.Name()
		if !strings.HasSuffix(fileName, ".json") {
			continue
		}
		s := strings.Split(fileName, ".")
		if len(s) == 5 {
			cachedFilePaths = append(cachedFilePaths, fileName)
		}
	}
	return cachedFilePaths
}

func (gpp *GitPersistenceProvider) persistToDisk(folderHashedPath, commitHash string, p product.Product, inputToCache []snyk.Issue) error {
	filePath := getLocalFilePath(folderHashedPath, commitHash, p)
	data, err := json.Marshal(inputToCache)
	if err != nil {
		return err
	}
	return afero.WriteFile(gpp.fs, filePath, data, 0644)
}

func (gpp *GitPersistenceProvider) deletePersistedFile(hash string, commitHash string, p product.Product) error {
	filePath := getLocalFilePath(hash, commitHash, p)
	err := gpp.fs.Remove(filePath)
	return err
}

func (gpp *GitPersistenceProvider) ensureCacheDirExists() error {
	dirPath := getCacheDirPath()
	if _, err := gpp.fs.Stat(dirPath); os.IsNotExist(err) {
		err = gpp.fs.Mkdir(dirPath, 0644)
		return err
	}
	return nil
}

func getCacheDirPath() string {
	return filepath.Join(xdg.CacheHome, CacheFolder)
}

func getLocalFilePath(filePathHash string, commitHash string, p product.Product) string {
	productName := p.ToProductCodename()
	return filepath.Join(getCacheDirPath(), fmt.Sprintf("%s.%s.%s.%s.json", SchemaVersion, filePathHash, commitHash, productName))
}

func hashPath(path string) (string, error) {
	h := murmur3.New64()
	_, err := h.Write([]byte(path))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum64()), nil
}
