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
	_ ScanSnapshotPersister = (*GitPersistenceProvider)(nil)
)

type hashedFolderPath string

type ScanSnapshotPersister interface {
	Clear()
	ClearForProduct(folderPath string, commitHash string, p product.Product) error
	Init() error
	Add(folderPath, commitHash string, issueList []snyk.Issue, p product.Product) error
	GetPersistedIssueList(folderPath string, p product.Product) ([]snyk.Issue, error)
	Exists(folderPath, commitHash string, p product.Product) bool
}

type productCommitHashMap map[product.Product]string

type GitPersistenceProvider struct {
	cache  map[hashedFolderPath]productCommitHashMap
	logger *zerolog.Logger
	mutex  sync.Mutex
	fs     afero.Fs
}

func NewGitPersistenceProvider(logger *zerolog.Logger, fs afero.Fs) *GitPersistenceProvider {
	return &GitPersistenceProvider{
		cache:  make(map[hashedFolderPath]productCommitHashMap),
		logger: logger,
		mutex:  sync.Mutex{},
		fs:     fs,
	}
}

func (gpp *GitPersistenceProvider) Clear() {
	gpp.mutex.Lock()
	defer gpp.mutex.Unlock()

	filePaths, err := gpp.getPersistedCachedFilePaths()
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to load cached file paths")
	}
	for _, filePath := range filePaths {
		fullPath := filepath.Join(getCacheDirPath(), filePath)
		err = gpp.deleteFile(fullPath)
		if err != nil {
			gpp.logger.Error().Err(err).Msg("failed to remove file " + filePath)
		}
	}
	gpp.cache = make(map[hashedFolderPath]productCommitHashMap)
}

func (gpp *GitPersistenceProvider) deleteFile(fullPath string) error {
	gpp.logger.Debug().Msg("deleting cached scan file " + fullPath)
	err := gpp.fs.Remove(fullPath)
	if err != nil {
		return err
	}
	return nil
}

func (gpp *GitPersistenceProvider) ClearForProduct(folderPath, commitHash string, p product.Product) error {
	gpp.mutex.Lock()
	defer gpp.mutex.Unlock()

	hash, err := hashPath(folderPath)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to hash path " + folderPath)
	}

	err = gpp.deleteFromCache(hash, commitHash, p)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to delete cached scan for product: " + p.ToProductCodename() + " for folder: " + folderPath)
		return err
	}

	filePath := getLocalFilePath(hash, commitHash, p)
	err = gpp.deleteFile(filePath)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to remove file: " + folderPath)
	}

	return err
}

func (gpp *GitPersistenceProvider) deleteFromCache(hash hashedFolderPath, commitHash string, p product.Product) error {
	pchm, exists := gpp.cache[hash]
	if !exists {
		return errors.New("hashed folder path doesn't exist in cache")
	}

	currentCommitHash, pchExists := pchm[p]
	if !pchExists {
		return errors.New("product doesn't exist in cache")
	}

	if currentCommitHash != commitHash {
		return errors.New("commit hashes don't match")
	}

	delete(gpp.cache[hash], p)

	return nil
}

func (gpp *GitPersistenceProvider) Init() error {
	gpp.mutex.Lock()
	defer gpp.mutex.Unlock()

	err := gpp.ensureCacheDirExists()
	if err != nil {
		gpp.logger.Error().Err(err).Msg("could not create cache dir")
		return err
	}

	filePaths, err := gpp.getPersistedCachedFilePaths()
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to load cached file paths")
		return err
	}
	for _, filePath := range filePaths {
		// file name structure is schema.hashedFolderPath.commitHash.productName.json
		s := strings.Split(filePath, ".")
		hash := hashedFolderPath(s[1])
		commitHash := s[2]
		p := product.ToProduct(s[3])
		gpp.createOrAppendToCache(hash, commitHash, p)
	}

	return nil
}

func (gpp *GitPersistenceProvider) GetPersistedIssueList(folderPath string, p product.Product) ([]snyk.Issue, error) {
	commitHash, err := gpp.getProductCommitHash(folderPath, p)
	if commitHash == "" || err != nil {
		return nil, err
	}

	hash, err := hashPath(folderPath)
	if err != nil {
		return nil, err
	}
	filePath := getLocalFilePath(hash, commitHash, p)
	content, err := afero.ReadFile(gpp.fs, filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = gpp.deleteFromCache(hash, commitHash, p)
			if err != nil {
				gpp.logger.Error().Err(err).Msg("failed to remove file from cache: " + filePath)
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

func (gpp *GitPersistenceProvider) Exists(folderPath, commitHash string, p product.Product) bool {
	existingCommitHash, err := gpp.getProductCommitHash(folderPath, p)
	if err != nil || existingCommitHash != commitHash {
		return false
	}

	hash, err := hashPath(folderPath)
	if err != nil {
		return false
	}

	exists := gpp.scanSnapshotExistsOnDisk(hash, commitHash, p)
	return exists
}

func (gpp *GitPersistenceProvider) scanSnapshotExistsOnDisk(hash hashedFolderPath, commitHash string, p product.Product) bool {
	filePath := getLocalFilePath(hash, commitHash, p)
	if _, err := gpp.fs.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	return true
}

func (gpp *GitPersistenceProvider) getProductCommitHash(folderPath string, p product.Product) (commitHash string, err error) {
	gpp.mutex.Lock()
	defer gpp.mutex.Unlock()

	hash, err := hashPath(folderPath)
	if err != nil {
		return "", err
	}
	pchMap, ok := gpp.cache[hash]
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

	shouldPersist := gpp.shouldPersist(hash, commitHash, p)
	if !shouldPersist {
		return nil
	}
	err = gpp.deleteFileIfDifferentHash(hash, commitHash, p)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to delete file from disk in " + folderPath)
		return err
	}
	err = gpp.persistToDisk(hash, commitHash, p, issueList)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to persist cache to disk for commitHash " + commitHash)
		return err
	}

	gpp.createOrAppendToCache(hash, commitHash, p)

	return nil
}

func (gpp *GitPersistenceProvider) shouldPersist(folderPathHash hashedFolderPath, commitHash string, p product.Product) bool {
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

	return true
}

func (gpp *GitPersistenceProvider) deleteFileIfDifferentHash(folderPathHash hashedFolderPath, commitHash string, p product.Product) error {
	pchm, pchmExists := gpp.cache[folderPathHash]
	if !pchmExists {
		return nil
	}

	ch, commitHashExists := pchm[p]
	if !commitHashExists {
		return nil
	}

	if ch == commitHash {
		return nil
	}
	filePath := getLocalFilePath(folderPathHash, commitHash, p)
	err := gpp.deleteFile(filePath)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to remove persisted scan file for product " + p.ToProductCodename())
	}

	err = gpp.deleteFromCache(folderPathHash, commitHash, p)
	if err != nil {
		gpp.logger.Error().Err(err).Msg("failed to delete cached scan for product: " + p.ToProductCodename())
		return err
	}

	return nil
}

func (gpp *GitPersistenceProvider) createOrAppendToCache(pathHash hashedFolderPath, commitHash string, product product.Product) {
	pchm, exists := gpp.cache[pathHash]
	if !exists {
		pchm = make(productCommitHashMap)
	}
	pchm[product] = commitHash
	gpp.cache[pathHash] = pchm
}

func (gpp *GitPersistenceProvider) getPersistedCachedFilePaths() (cachedFilePaths []string, err error) {
	entries, err := afero.ReadDir(gpp.fs, getCacheDirPath())
	if err != nil {
		return cachedFilePaths, err
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
	return cachedFilePaths, nil
}

func (gpp *GitPersistenceProvider) persistToDisk(folderHashedPath hashedFolderPath, commitHash string, p product.Product, inputToCache []snyk.Issue) error {
	filePath := getLocalFilePath(folderHashedPath, commitHash, p)
	data, err := json.Marshal(inputToCache)
	if err != nil {
		return err
	}
	gpp.logger.Debug().Msg("persisting scan results in file " + filePath)
	return afero.WriteFile(gpp.fs, filePath, data, 0644)
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

func getLocalFilePath(folderPathHash hashedFolderPath, commitHash string, p product.Product) string {
	productName := p.ToProductCodename()
	return filepath.Join(getCacheDirPath(), fmt.Sprintf("%s.%s.%s.%s.json", SchemaVersion, folderPathHash, commitHash, productName))
}

func hashPath(path string) (hashedFolderPath, error) {
	h := murmur3.New64()
	_, err := h.Write([]byte(path))
	if err != nil {
		return "", err
	}
	hash := fmt.Sprintf("%x", h.Sum64())
	return hashedFolderPath(hash), nil
}
