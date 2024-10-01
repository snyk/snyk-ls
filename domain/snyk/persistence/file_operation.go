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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/snyk/snyk-ls/domain/snyk"
	gitconfig "github.com/snyk/snyk-ls/internal/git_config"
	"github.com/snyk/snyk-ls/internal/product"
)

func (g *GitPersistenceProvider) persistToDisk(cacheDir string, folderHashedPath hashedFolderPath, commitHash string, p product.Product, inputToCache []snyk.Issue) error {
	filePath := getLocalFilePath(cacheDir, folderHashedPath, commitHash, p)
	data, err := json.Marshal(inputToCache)
	if err != nil {
		return err
	}
	g.logger.Debug().Msg("persisting scan results in file " + filePath)
	return os.WriteFile(filePath, data, 0644)
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

func (g *GitPersistenceProvider) ensureCacheDirExists(folderPath string) (string, error) {
	g.logger.Debug().Msg("attempting to determine .git folder path")
	cacheDir, err := g.snykCacheDir(folderPath)
	if err != nil {
		return "", err
	}

	if _, err = os.Stat(cacheDir); os.IsNotExist(err) {
		err = os.Mkdir(cacheDir, 0700)
		if err != nil {
			return "", err
		}
	}
	return cacheDir, nil
}

func (g *GitPersistenceProvider) snykCacheDir(folderPath string) (string, error) {
	gitFolder, err := gitconfig.GitFolderPath(folderPath)
	if err != nil {
		return "", err
	}

	cacheDir := filepath.Join(gitFolder, CacheFolder)

	return cacheDir, nil
}

func getLocalFilePath(cacheDir string, folderPathHash hashedFolderPath, commitHash string, p product.Product) string {
	productName := p.ToProductCodename()
	return filepath.Join(cacheDir, fmt.Sprintf("%s.%s.%s.%s.json", SchemaVersion, folderPathHash, commitHash, productName))
}

func (g *GitPersistenceProvider) snapshotExistsOnDisk(cacheDir string, hash hashedFolderPath, commitHash string, p product.Product) bool {
	filePath := getLocalFilePath(cacheDir, hash, commitHash, p)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	return true
}

func (g *GitPersistenceProvider) deleteFile(fullPath string) error {
	g.logger.Debug().Msgf("deleting cached scan file %s", fullPath)
	err := os.Remove(fullPath)
	if err != nil {
		return err
	}
	return nil
}

func (g *GitPersistenceProvider) isExpired(schemaVersion string, fullFilePath string) bool {
	// if file has incorrect schema we just delete it
	if schemaVersion != SchemaVersion {
		return true
	}

	// Check last modified date
	fileInfo, err := os.Stat(fullFilePath)
	if err != nil {
		g.logger.Error().Err(err).Msg("couldn't stat file " + fullFilePath)
		return true
	}

	// If elapsed time is > ExpirationInSeconds, delete the file
	if time.Since(fileInfo.ModTime()) > time.Duration(ExpirationInSeconds)*time.Second {
		return true
	}

	return false
}
