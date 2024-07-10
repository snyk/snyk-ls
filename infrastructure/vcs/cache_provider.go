package vcs

import (
	"encoding/json"
	"fmt"
	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/spaolacci/murmur3"
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

type GitCacheProvider struct {
	Cache  map[string]string
	logger *zerolog.Logger
	mutex  sync.Mutex
}

func NewCacheProvider(logger *zerolog.Logger) *GitCacheProvider {
	return &GitCacheProvider{
		Cache:  make(map[string]string),
		logger: logger,
		mutex:  sync.Mutex{},
	}
}

func CurrentCache() *GitCacheProvider {
	mutex.Lock()
	defer mutex.Unlock()
	if currentCacheProvider == nil {
		logger := config.CurrentConfig().Logger()
		currentCacheProvider = NewCacheProvider(logger)
	}
	return currentCacheProvider
}

func (cp *GitCacheProvider) LoadCache() error {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	entries, err := os.ReadDir(filepath.Join(xdg.CacheHome, CacheFolder))
	if err != nil {
		return err
	}

	for _, entry := range entries {
		fileName := entry.Name()
		if !strings.HasSuffix(fileName, ".json") {
			continue
		}
		// file name should be pathHash.commitHash.json
		s := strings.Split(fileName, ".")
		if len(s) == 3 {
			cp.Cache[s[0]] = s[1]
		}
	}
	return nil
}
func (cp *GitCacheProvider) GetCacheValue(folderPath string) (string, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	hashedFolderPath, err := hashPath(folderPath)
	if err != nil {
		return "", err
	}
	commitHash, ok := cp.Cache[hashedFolderPath]
	if !ok {
		return "", nil
	}
	return commitHash, nil
}

func (cp *GitCacheProvider) GetPersistedCache(folderPath string) ([]snyk.Issue, error) {
	commitHash, err := cp.GetCacheValue(folderPath)
	if err != nil {
		return nil, err
	}

	hashedFolderPath, err := hashPath(folderPath)
	if err != nil {
		return nil, err
	}

	filePath := cp.getFilePath(hashedFolderPath, commitHash)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var results []snyk.Issue
	err = json.Unmarshal(content, &results)

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (cp *GitCacheProvider) persistToDisk(hash, commitHash string, inputToCache []snyk.Issue) error {
	filePath := cp.getFilePath(hash, commitHash)
	data, err := json.Marshal(inputToCache)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

func (cp *GitCacheProvider) AddToCache(folderPath, commitHash string, inputToPersist []snyk.Issue) error {
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
	if existingCommit, exists := cp.Cache[hash]; exists {
		if existingCommit == commitHash {
			return nil
		}

		filePath := cp.getFilePath(hash, existingCommit)
		err = os.Remove(filePath)
		if err != nil {
			cp.logger.Error().Err(err).Msg("failed to remove file" + filePath)
		}
		delete(cp.Cache, hash)
	}

	err = cp.persistToDisk(hash, commitHash, inputToPersist)
	if err != nil {
		cp.logger.Error().Err(err).Msg("failed to persist cache to disk for commitHash " + commitHash)
		return err
	}

	cp.Cache[hash] = commitHash

	return nil
}

func (cp *GitCacheProvider) ensureCacheDirExists() error {
	dirPath := cp.getDirPath()
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err = os.Mkdir(dirPath, 0644)
		return err
	}

	return nil
}

func (cp *GitCacheProvider) getDirPath() string {
	return filepath.Join(xdg.CacheHome, CacheFolder)
}

func (cp *GitCacheProvider) getFilePath(filePathHash, commitHash string) string {
	return filepath.Join(cp.getDirPath(), fmt.Sprintf("%s.%s.json", filePathHash, commitHash))
}

func hashPath(path string) (string, error) {
	h := murmur3.New64()
	_, err := h.Write([]byte(path))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum64()), nil
}
