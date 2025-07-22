/*
 * © 2024 Snyk Limited All rights reserved.
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
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ProtocolExtractor extracts protocol version from plugin source
type ProtocolExtractor interface {
	ExtractProtocolVersion(plugin IDEPlugin, tag string) (string, error)
}

// GitHubProtocolExtractor extracts protocol version by downloading source archives
type GitHubProtocolExtractor struct {
	httpClient *http.Client
	cache      *Cache
}

// NewProtocolExtractor creates a new protocol extractor
func NewProtocolExtractor(cache *Cache) ProtocolExtractor {
	return &GitHubProtocolExtractor{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		cache: cache,
	}
}

// ExtractProtocolVersion extracts the protocol version from a plugin release
func (e *GitHubProtocolExtractor) ExtractProtocolVersion(plugin IDEPlugin, tag string) (string, error) {
	// Check cache first
	cacheKey := GetReleaseCacheKey(plugin.Repo, tag)
	var cachedVersion string
	if found, err := e.cache.Get(cacheKey, &cachedVersion); found && err == nil {
		return cachedVersion, nil
	}

	// Download and extract from source
	version, err := e.extractFromSource(plugin, tag)
	if err != nil {
		return "", err
	}

	// Cache the result
	_ = e.cache.Set(cacheKey, version, 7*24*time.Hour) // Cache for 7 days

	return version, nil
}

// extractFromSource downloads the source archive and extracts protocol version
func (e *GitHubProtocolExtractor) extractFromSource(plugin IDEPlugin, tag string) (string, error) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "plugin-source-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)

	// Download source archive
	archiveURL := fmt.Sprintf("https://github.com/%s/%s/archive/refs/tags/%s.tar.gz",
		plugin.Owner, plugin.Repo, tag)

	resp, err := e.httpClient.Get(archiveURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download source: %s", resp.Status)
	}

	// Extract tar.gz
	if err := extractTarGz(resp.Body, tempDir); err != nil {
		return "", err
	}

	// Find protocol version based on plugin type
	switch plugin.Repo {
	case "vscode-extension":
		return e.extractVSCodeProtocol(tempDir)
	case "snyk-intellij-plugin":
		return e.extractIntelliJProtocol(tempDir)
	case "snyk-visual-studio-plugin":
		return e.extractVisualStudioProtocol(tempDir)
	case "snyk-eclipse-plugin":
		return e.extractEclipseProtocol(tempDir)
	default:
		return "", fmt.Errorf("unknown plugin: %s", plugin.Repo)
	}
}

// extractVSCodeProtocol extracts protocol version from VSCode extension
func (e *GitHubProtocolExtractor) extractVSCodeProtocol(sourceDir string) (string, error) {
	// Look for PROTOCOL_VERSION in TypeScript files
	pattern := regexp.MustCompile(`(?m)^export\s+const\s+PROTOCOL_VERSION\s*=\s*(\d+)`)

	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		if strings.HasSuffix(path, ".ts") && strings.Contains(path, "constants") {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil // Continue walking
			}

			matches := pattern.FindSubmatch(content)
			if len(matches) > 1 {
				return fmt.Errorf("FOUND:%s", string(matches[1]))
			}
		}
		return nil
	})

	if err != nil && strings.HasPrefix(err.Error(), "FOUND:") {
		return strings.TrimPrefix(err.Error(), "FOUND:"), nil
	}

	return "", fmt.Errorf("protocol version not found in VSCode extension")
}

// extractIntelliJProtocol extracts protocol version from IntelliJ plugin
func (e *GitHubProtocolExtractor) extractIntelliJProtocol(sourceDir string) (string, error) {
	// Look for protocol version in Kotlin/Java files
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)(?:val|const)\s+PROTOCOL_VERSION\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)private\s+static\s+final\s+(?:String|int)\s+PROTOCOL_VERSION\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)requiredProtocolVersion["\s:=]+(\d+)`),
	}

	var lastErr error
	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		if strings.HasSuffix(path, ".kt") || strings.HasSuffix(path, ".java") {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil // Continue walking
			}

			for _, pattern := range patterns {
				matches := pattern.FindSubmatch(content)
				if len(matches) > 1 {
					return fmt.Errorf("FOUND:%s", string(matches[1]))
				}
			}
		}
		return nil
	})

	if err != nil && strings.HasPrefix(err.Error(), "FOUND:") {
		return strings.TrimPrefix(err.Error(), "FOUND:"), nil
	}

	lastErr = fmt.Errorf("protocol version not found in IntelliJ plugin")
	return "", lastErr
}

// extractVisualStudioProtocol extracts protocol version from Visual Studio plugin
func (e *GitHubProtocolExtractor) extractVisualStudioProtocol(sourceDir string) (string, error) {
	// Look for protocol version in C# files
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)(?:const|static)\s+(?:readonly\s+)?(?:string|int)\s+ProtocolVersion\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)RequiredProtocolVersion\s*[=:]\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)"requiredProtocolVersion"\s*:\s*"?(\d+)"?`),
	}

	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		if strings.HasSuffix(path, ".cs") || strings.HasSuffix(path, ".json") {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil // Continue walking
			}

			for _, pattern := range patterns {
				matches := pattern.FindSubmatch(content)
				if len(matches) > 1 {
					return fmt.Errorf("FOUND:%s", string(matches[1]))
				}
			}
		}
		return nil
	})

	if err != nil && strings.HasPrefix(err.Error(), "FOUND:") {
		return strings.TrimPrefix(err.Error(), "FOUND:"), nil
	}

	return "", fmt.Errorf("protocol version not found in Visual Studio plugin")
}

// extractEclipseProtocol extracts protocol version from Eclipse plugin
func (e *GitHubProtocolExtractor) extractEclipseProtocol(sourceDir string) (string, error) {
	// Look for protocol version in Java files and manifest
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)PROTOCOL_VERSION\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)protocolVersion\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)requiredProtocolVersion["\s:=]+(\d+)`),
	}

	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		if strings.HasSuffix(path, ".java") || strings.HasSuffix(path, ".xml") ||
			strings.HasSuffix(path, "MANIFEST.MF") {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil // Continue walking
			}

			for _, pattern := range patterns {
				matches := pattern.FindSubmatch(content)
				if len(matches) > 1 {
					return fmt.Errorf("FOUND:%s", string(matches[1]))
				}
			}
		}
		return nil
	})

	if err != nil && strings.HasPrefix(err.Error(), "FOUND:") {
		return strings.TrimPrefix(err.Error(), "FOUND:"), nil
	}

	return "", fmt.Errorf("protocol version not found in Eclipse plugin")
}

// extractTarGz extracts a tar.gz archive to a directory
func extractTarGz(r io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}

			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}

	return nil
}
