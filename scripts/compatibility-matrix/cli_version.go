/*
 * © 2025 Snyk Limited All rights reserved.
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

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/snyk/snyk-ls/internal/constants"
)

// CLIVersionMapper maps protocol versions to CLI versions
type CLIVersionMapper struct {
	httpClient *http.Client
	cache      *Cache
}

// NewCLIVersionMapper creates a new CLI version mapper
func NewCLIVersionMapper(cache *Cache) *CLIVersionMapper {
	return &CLIVersionMapper{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: cache,
	}
}

// GetCLIVersion gets the latest compatible CLI version for a protocol version
func (m *CLIVersionMapper) GetCLIVersion(protocolVersion string) (string, error) {
	// Check cache first
	cacheKey := GetCLIVersionCacheKey(protocolVersion)
	var cachedVersion string
	if found, err := m.cache.Get(cacheKey, &cachedVersion); found && err == nil {
		return cachedVersion, nil
	}

	// Fetch from API
	version, err := m.fetchCLIVersion(protocolVersion)
	if err != nil {
		return "", err
	}

	// Cache the result
	if err := m.cache.Set(cacheKey, version, 24*time.Hour); err != nil {
		log.Printf("Warning: failed to cache CLI version for %s: %v", cacheKey, err)
	}

	return version, nil
}

// fetchCLIVersion fetches the CLI version from Snyk API
func (m *CLIVersionMapper) fetchCLIVersion(protocolVersion string) (string, error) {
	// Use stable channel for CLI versions
	url := fmt.Sprintf("%s/cli/stable/ls-protocol-version-%s", constants.SNYK_CLI_DOWNLOAD_BASE_URL, protocolVersion)

	resp, err := m.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch CLI version: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch CLI version: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	version := strings.TrimSpace(string(body))
	if version == "" {
		return "", fmt.Errorf("empty CLI version response")
	}

	// Ensure version has v prefix
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	return version, nil
}
