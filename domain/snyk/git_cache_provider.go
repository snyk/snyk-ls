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
	CacheFolder = "snyk_scan"
)

var (
	mutex                = &sync.Mutex{}
	currentCacheProvider *GitCacheProvider
)

type productCommitHash struct {
	commitHash string
	product    product.Product
}

type GitCacheProvider struct {
	cache  map[string]productCommitHash
	logger *zerolog.Logger
	mutex  sync.Mutex
	fs     afero.Fs
}

func NewGitCacheProvider(logger *zerolog.Logger, fs afero.Fs) *GitCacheProvider {
	currentCacheProvider = &GitCacheProvider{
		cache:  make(map[string]productCommitHash),
		logger: logger,
		mutex:  sync.Mutex{},
		fs:     fs,
	}
	return currentCacheProvider
}

func CurrentGitCache() *GitCacheProvider {
	mutex.Lock()
	defer mutex.Unlock()

	return currentCacheProvider
}

func (cp *GitCacheProvider) Clear() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	filePaths := cp.getPersistedCachedFilePaths()
	for _, filePath := range filePaths {
		filePathHash, err := hashPath(filePath)
		if err != nil {
			cp.logger.Error().Err(err).Msg("failed hash path " + filePath)
			continue
		}

		if pch, ok := cp.cache[filePathHash]; ok {
			err = cp.deletePersistedFile(filePathHash, pch)
			if err != nil {
				cp.logger.Error().Err(err).Msg("failed remove file " + filePath)
			}
		}
	}
	cp.cache = make(map[string]productCommitHash)
}

func (cp *GitCacheProvider) ClearIssues(path string, product product.Product) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	hash, err := hashPath(path)
	if err != nil {
		cp.logger.Error().Err(err).Msg("failed to hash path " + path)
	}
	if pch, exists := cp.cache[hash]; exists && pch.product == product {
		err = cp.deletePersistedFile(hash, pch)
		if err != nil {
			cp.logger.Error().Err(err).Msg("failed to remove file: " + path)
		}
		delete(cp.cache, hash)
	}
}

func (cp *GitCacheProvider) LoadCache() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	filePaths := cp.getPersistedCachedFilePaths()
	for _, filePath := range filePaths {
		s := strings.Split(filePath, ".")
		cp.cache[s[0]] = productCommitHash{commitHash: s[1], product: product.ToProduct(s[2])}
	}
}

func (cp *GitCacheProvider) GetCommitHashFor(folderPath string) (string, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	hashedFolderPath, err := hashPath(folderPath)
	if err != nil {
		return "", err
	}
	pch, ok := cp.cache[hashedFolderPath]
	if !ok {
		return "", nil
	}
	return pch.commitHash, nil
}

func (cp *GitCacheProvider) GetPersistedIssueList(folderPath string, product product.Product) ([]Issue, error) {
	commitHash, err := cp.GetCommitHashFor(folderPath)
	if err != nil {
		return nil, err
	}

	hashedFolderPath, err := hashPath(folderPath)
	if err != nil {
		return nil, err
	}
	pch := productCommitHash{commitHash: commitHash, product: product}
	filePath := getLocalFilePath(hashedFolderPath, pch)
	content, err := afero.ReadFile(cp.fs, filePath)
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

func (cp *GitCacheProvider) AddToCache(folderPath, commitHash string, issueList []Issue, product product.Product) error {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	err := cp.ensureCacheDirExists()
	if err != nil {
		cp.logger.Error().Err(err).Msg("could not create cache dir")
		return err
	}
	hash, err := hashPath(folderPath)
	if err != nil {
		cp.logger.Error().Err(err).Msg("could not hash path" + folderPath)
		return err
	}

	if pch, exists := cp.cache[hash]; exists && pch.product == product {
		if pch.commitHash == commitHash {
			return nil
		}

		filePath := getLocalFilePath(hash, pch)
		err = cp.fs.Remove(filePath)
		if err != nil {
			cp.logger.Error().Err(err).Msg("failed to remove file" + filePath)
		}
		delete(cp.cache, hash)
	}

	err = cp.persistToDisk(hash, commitHash, issueList, product)
	if err != nil {
		cp.logger.Error().Err(err).Msg("failed to persist cache to disk for commitHash " + commitHash)
		return err
	}

	cp.cache[hash] = productCommitHash{commitHash: commitHash, product: product}

	return nil
}

func (cp *GitCacheProvider) getPersistedCachedFilePaths() (cachedFilePaths []string) {
	entries, err := afero.ReadDir(cp.fs, filepath.Join(xdg.CacheHome, CacheFolder))
	if err != nil {
		return cachedFilePaths
	}

	for _, entry := range entries {
		fileName := entry.Name()
		if !strings.HasSuffix(fileName, ".json") {
			continue
		}
		s := strings.Split(fileName, ".")
		if len(s) == 4 {
			cachedFilePaths = append(cachedFilePaths, fileName)
		}
	}
	return cachedFilePaths
}

func (cp *GitCacheProvider) persistToDisk(hash, commitHash string, inputToCache []Issue, product product.Product) error {
	pch := productCommitHash{commitHash: commitHash, product: product}
	filePath := getLocalFilePath(hash, pch)
	data, err := json.Marshal(inputToCache)
	if err != nil {
		return err
	}
	return afero.WriteFile(cp.fs, filePath, data, 0644)
}

func (cp *GitCacheProvider) deletePersistedFile(hash string, pch productCommitHash) error {
	filePath := getLocalFilePath(hash, pch)
	err := cp.fs.Remove(filePath)
	return err
}

func (cp *GitCacheProvider) ensureCacheDirExists() error {
	dirPath := getCacheDirPath()
	if _, err := cp.fs.Stat(dirPath); os.IsNotExist(err) {
		err = cp.fs.Mkdir(dirPath, 0644)
		return err
	}
	return nil
}

func getCacheDirPath() string {
	return filepath.Join(xdg.CacheHome, CacheFolder)
}

func getLocalFilePath(filePathHash string, pch productCommitHash) string {
	return filepath.Join(getCacheDirPath(), fmt.Sprintf("%s.%s.%s.json", filePathHash, pch.commitHash, product.ToProductCodename(pch.product)))
}

func hashPath(path string) (string, error) {
	h := murmur3.New64()
	_, err := h.Write([]byte(path))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum64()), nil
}
