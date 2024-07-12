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

package snyk

import (
	"encoding/json"
	"fmt"
	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/spaolacci/murmur3"
	"github.com/spf13/afero"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	CacheFolder   = "snyk_scan"
	SchemaVersion = "v1"
)

var (
	currentCacheProvider *GitCacheProvider
)

type productCommitHashMap map[product.Product]string

type GitCacheProvider struct {
	cache  map[string]productCommitHashMap
	logger *zerolog.Logger
	mutex  sync.Mutex
	fs     afero.Fs
}

func NewGitCacheProvider(logger *zerolog.Logger, fs afero.Fs) *GitCacheProvider {
	currentCacheProvider = &GitCacheProvider{
		cache:  make(map[string]productCommitHashMap),
		logger: logger,
		mutex:  sync.Mutex{},
		fs:     fs,
	}
	return currentCacheProvider
}

func CurrentGitCache() *GitCacheProvider {
	return currentCacheProvider
}

func (gcp *GitCacheProvider) Clear() {
	gcp.mutex.Lock()
	defer gcp.mutex.Unlock()

	filePaths := gcp.getPersistedCachedFilePaths()
	for _, filePath := range filePaths {
		gcp.deleteAllPersistedFilesForPath(filePath)
	}
	gcp.cache = make(map[string]productCommitHashMap)
}

func (gcp *GitCacheProvider) deleteAllPersistedFilesForPath(filePath string) {
	filePathHash, err := hashPath(filePath)
	if err != nil {
		gcp.logger.Error().Err(err).Msg("failed hash path " + filePath)
		return
	}
	if pchm, exists := gcp.cache[filePathHash]; exists {
		for p, pch := range pchm {
			err = gcp.deletePersistedFile(filePathHash, pch, p)
			if err != nil {
				gcp.logger.Error().Err(err).Msg("failed remove file " + filePath)
			}
		}
	}
}

func (gcp *GitCacheProvider) ClearIssues(path string, p product.Product) {
	gcp.mutex.Lock()
	defer gcp.mutex.Unlock()
	hash, err := hashPath(path)
	if err != nil {
		gcp.logger.Error().Err(err).Msg("failed to hash path " + path)
	}
	pchm, exists := gcp.cache[hash]
	if !exists {
		return
	}

	pch, pchExists := pchm[p]
	if !pchExists {
		return
	}
	err = gcp.deletePersistedFile(hash, pch, p)
	if err != nil {
		gcp.logger.Error().Err(err).Msg("failed to remove file: " + path)
	}
	delete(gcp.cache, hash)
}

func (gcp *GitCacheProvider) LoadCache() {
	gcp.mutex.Lock()
	defer gcp.mutex.Unlock()

	filePaths := gcp.getPersistedCachedFilePaths()
	for _, filePath := range filePaths {
		s := strings.Split(filePath, ".")
		p := product.ToProduct(s[3])
		gcp.CreateOrAppendToCache(s[1], s[2], p)
	}
}

func (gcp *GitCacheProvider) GetPersistedIssueList(folderPath string, p product.Product) ([]Issue, error) {
	pch, err := gcp.getProductCommitHash(folderPath, p)
	if err != nil {
		return nil, err
	}

	hashedFolderPath, err := hashPath(folderPath)
	if err != nil {
		return nil, err
	}
	filePath := getLocalFilePath(hashedFolderPath, pch, p)
	content, err := afero.ReadFile(gcp.fs, filePath)
	if err != nil {
		return nil, err
	}

	var results []Issue
	err = json.Unmarshal(content, &results)

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (gcp *GitCacheProvider) getProductCommitHash(folderPath string, p product.Product) (commitHash string, err error) {
	gcp.mutex.Lock()
	defer gcp.mutex.Unlock()

	hashedFolderPath, err := hashPath(folderPath)
	if err != nil {
		return "", err
	}
	pchMap, ok := gcp.cache[hashedFolderPath]
	if !ok {
		return "", nil
	}
	commitHash = pchMap[p]
	return commitHash, nil
}

func (gcp *GitCacheProvider) AddToCache(folderPath, commitHash string, issueList []Issue, p product.Product) error {
	gcp.mutex.Lock()
	defer gcp.mutex.Unlock()

	err := gcp.ensureCacheDirExists()
	if err != nil {
		gcp.logger.Error().Err(err).Msg("could not create cache dir")
		return err
	}
	hash, err := hashPath(folderPath)
	if err != nil {
		gcp.logger.Error().Err(err).Msg("could not hash path" + folderPath)
		return err
	}

	shouldPersist := gcp.checkAndRemoveExistingFile(hash, commitHash, p)
	if !shouldPersist {
		return nil
	}
	err = gcp.persistToDisk(hash, commitHash, p, issueList)
	if err != nil {
		gcp.logger.Error().Err(err).Msg("failed to persist cache to disk for commitHash " + commitHash)
		return err
	}

	gcp.CreateOrAppendToCache(hash, commitHash, p)

	return nil
}

func (gcp *GitCacheProvider) checkAndRemoveExistingFile(folderPathHash string, commitHash string, p product.Product) bool {
	pchm, pchmExists := gcp.cache[folderPathHash]
	if !pchmExists {
		return true
	}

	ch, pchExists := pchm[p]
	if !pchExists {
		return true
	}

	if ch == commitHash {
		return false
	}

	filePath := getLocalFilePath(folderPathHash, ch, p)
	err := gcp.fs.Remove(filePath)
	if err != nil {
		gcp.logger.Error().Err(err).Msg("failed to remove file " + filePath)
		return true
	}
	delete(gcp.cache, folderPathHash)

	return true
}

func (gcp *GitCacheProvider) CreateOrAppendToCache(pathHash string, commitHash string, product product.Product) {
	pchm, exists := gcp.cache[pathHash]
	if !exists {
		pchm = make(productCommitHashMap)
	}
	pchm[product] = commitHash
	gcp.cache[pathHash] = pchm
}

func (gcp *GitCacheProvider) getPersistedCachedFilePaths() (cachedFilePaths []string) {
	entries, err := afero.ReadDir(gcp.fs, filepath.Join(xdg.CacheHome, CacheFolder))
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

func (gcp *GitCacheProvider) persistToDisk(folderHashedPath, commitHash string, p product.Product, inputToCache []Issue) error {
	filePath := getLocalFilePath(folderHashedPath, commitHash, p)
	data, err := json.Marshal(inputToCache)
	if err != nil {
		return err
	}
	return afero.WriteFile(gcp.fs, filePath, data, 0644)
}

func (gcp *GitCacheProvider) deletePersistedFile(hash string, commitHash string, p product.Product) error {
	filePath := getLocalFilePath(hash, commitHash, p)
	err := gcp.fs.Remove(filePath)
	return err
}

func (gcp *GitCacheProvider) ensureCacheDirExists() error {
	dirPath := getCacheDirPath()
	if _, err := gcp.fs.Stat(dirPath); os.IsNotExist(err) {
		err = gcp.fs.Mkdir(dirPath, 0644)
		return err
	}
	return nil
}

func getCacheDirPath() string {
	return filepath.Join(xdg.CacheHome, CacheFolder)
}

func getLocalFilePath(filePathHash string, commitHash string, p product.Product) string {
	productName := product.ToProductCodename(p)
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
