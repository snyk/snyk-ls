/*
 * 2025 Snyk Limited
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

package trust

import (
	_ "embed"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

const (
	TrustedFoldersConfigKey = "trustedFolders"
	DisableTrustFlag        = "disable-trust"
)

type FolderTrust struct {
	logger *zerolog.Logger
	config configuration.Configuration
	mutex  sync.RWMutex
}

//go:embed trust.html
var SnykTrustPage string

func NewFolderTrust(logger *zerolog.Logger, config configuration.Configuration) *FolderTrust {
	return &FolderTrust{
		logger: logger,
		config: config,
	}
}

func normalizePath(folder string) string {
	return path.Clean(folder)
}

func folderContains(folderPath string, path string) bool {
	filePathSeparator := string(filepath.Separator)
	cleanPath := normalizePath(path)
	cleanFolderPath := normalizePath(folderPath)
	if !strings.HasSuffix(cleanFolderPath, filePathSeparator) {
		cleanFolderPath += filePathSeparator
	}

	// Check if the path is on a case-insensitive filesystem
	if runtime.GOOS == "windows" {
		cleanPath = strings.ToLower(cleanPath)
		cleanFolderPath = strings.ToLower(cleanFolderPath)
	}

	return strings.HasPrefix(cleanPath, cleanFolderPath) ||
		strings.HasPrefix(cleanPath+filePathSeparator, cleanFolderPath)
}

func (t *FolderTrust) IsFolderTrusted(folder string) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	for _, trustedFolder := range t.trustedFolders() {
		if folderContains(trustedFolder, folder) {
			return true
		}
	}
	return false
}

func (t *FolderTrust) TrustedFolders() []string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.trustedFolders()
}

func (t *FolderTrust) trustedFolders() []string {
	rawRes := t.config.Get(TrustedFoldersConfigKey)
	if rawRes != nil {
		return rawRes.([]string)
	}
	return []string{}
}

func (t *FolderTrust) AddTrustedFolder(folder string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.addTrustedFolder(folder)
}

func (t *FolderTrust) addTrustedFolder(folder string) {
	trustedFolders := t.trustedFolders()
	folder = normalizePath(folder)
	if slices.Contains(trustedFolders, folder) {
		return
	}
	trustedFolders = append(trustedFolders, folder)
	t.config.Set(TrustedFoldersConfigKey, trustedFolders)
}
