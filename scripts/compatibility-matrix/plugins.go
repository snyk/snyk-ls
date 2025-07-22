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
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// errStopWalk is a sentinel error used to stop filepath.Walk early
var errStopWalk = errors.New("stop walk")

// ProtocolVersionInfo contains both protocol version and semantic version
type ProtocolVersionInfo struct {
	ProtocolVersion string
	SemanticVersion string // Optional, used for Eclipse
}

// ProtocolExtractor extracts protocol version from plugin source
type ProtocolExtractor interface {
	ExtractProtocolVersion(plugin IDEPlugin, tag string) (*ProtocolVersionInfo, error)
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
func (e *GitHubProtocolExtractor) ExtractProtocolVersion(plugin IDEPlugin, tag string) (*ProtocolVersionInfo, error) {
	// Check cache first
	cacheKey := GetReleaseCacheKey(plugin.Repo, tag)
	var cachedVersion ProtocolVersionInfo
	if found, err := e.cache.Get(cacheKey, &cachedVersion); found && err == nil {
		return &cachedVersion, nil
	}

	// Download and extract from source
	versionInfo, err := e.extractFromSource(plugin, tag)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if err := e.cache.Set(cacheKey, versionInfo, 7*24*time.Hour); err != nil {
		log.Printf("Warning: failed to cache protocol version for %s: %v", cacheKey, err)
	}

	return versionInfo, nil
}

// extractFromSource downloads the source archive and extracts protocol version
func (e *GitHubProtocolExtractor) extractFromSource(plugin IDEPlugin, tag string) (*ProtocolVersionInfo, error) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "plugin-source-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	// Download source archive
	archiveURL := fmt.Sprintf("https://github.com/%s/%s/archive/refs/tags/%s.tar.gz",
		plugin.Owner, plugin.Repo, tag)

	resp, err := e.httpClient.Get(archiveURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download source: %s", resp.Status)
	}

	// Extract tar.gz
	if err := extractTarGz(resp.Body, tempDir); err != nil {
		return nil, err
	}

	// Find protocol version based on plugin type
	versionInfo := &ProtocolVersionInfo{}

	switch plugin.Repo {
	case "vscode-extension":
		protocolVersion, err := e.extractVSCodeProtocol(tempDir)
		if err != nil {
			return nil, err
		}
		versionInfo.ProtocolVersion = protocolVersion

	case "snyk-intellij-plugin":
		protocolVersion, err := e.extractIntelliJProtocol(tempDir)
		if err != nil {
			return nil, err
		}
		versionInfo.ProtocolVersion = protocolVersion

	case "snyk-visual-studio-plugin":
		protocolVersion, err := e.extractVisualStudioProtocol(tempDir)
		if err != nil {
			return nil, err
		}
		versionInfo.ProtocolVersion = protocolVersion

	case "snyk-eclipse-plugin":
		protocolVersion, err := e.extractEclipseProtocol(tempDir)
		if err != nil {
			return nil, err
		}
		versionInfo.ProtocolVersion = protocolVersion
		// Also extract semantic version for Eclipse
		versionInfo.SemanticVersion = e.extractEclipseSemanticVersion(tempDir)

	default:
		return nil, fmt.Errorf("unknown plugin: %s", plugin.Repo)
	}

	return versionInfo, nil
}

// extractVSCodeProtocol extracts protocol version from VSCode extension
func (e *GitHubProtocolExtractor) extractVSCodeProtocol(sourceDir string) (string, error) {
	// Look for PROTOCOL_VERSION in TypeScript files
	pattern := regexp.MustCompile(`(?m)^export\s+const\s+PROTOCOL_VERSION\s*=\s*(\d+)`)
	var protocolVersion string

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
				protocolVersion = string(matches[1])
				return errStopWalk
			}
		}
		return nil
	})

	if err != nil && !errors.Is(err, errStopWalk) {
		return "", err
	}

	if protocolVersion == "" {
		return "", fmt.Errorf("protocol version not found in VSCode extension")
	}

	return protocolVersion, nil
}

// extractIntelliJProtocol extracts protocol version from IntelliJ plugin
func (e *GitHubProtocolExtractor) extractIntelliJProtocol(sourceDir string) (string, error) {
	// Look for protocol version in Kotlin/Java files
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)(?:val|const)\s+PROTOCOL_VERSION\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)private\s+static\s+final\s+(?:String|int)\s+PROTOCOL_VERSION\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)requiredProtocolVersion["\s:=]+(\d+)`),
		regexp.MustCompile(`(?m)val\s+requiredLsProtocolVersion\s*=\s*"?(\d+)"?`),
	}
	var protocolVersion string

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
					protocolVersion = string(matches[1])
					return errStopWalk
				}
			}
		}
		return nil
	})

	if err != nil && !errors.Is(err, errStopWalk) {
		return "", err
	}

	if protocolVersion == "" {
		return "", fmt.Errorf("protocol version not found in IntelliJ plugin")
	}

	return protocolVersion, nil
}

// extractVisualStudioProtocol extracts protocol version from Visual Studio plugin
func (e *GitHubProtocolExtractor) extractVisualStudioProtocol(sourceDir string) (string, error) {
	// Look for protocol version in C# files
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)(?:const|static)\s+(?:readonly\s+)?(?:string|int)\s+ProtocolVersion\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)RequiredProtocolVersion\s*[=:]\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)"requiredProtocolVersion"\s*:\s*"?(\d+)"?`),
	}
	var protocolVersion string

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
					protocolVersion = string(matches[1])
					return errStopWalk
				}
			}
		}
		return nil
	})

	if err != nil && !errors.Is(err, errStopWalk) {
		return "", err
	}

	if protocolVersion == "" {
		return "", fmt.Errorf("protocol version not found in Visual Studio plugin")
	}

	return protocolVersion, nil
}

// extractEclipseProtocol extracts protocol version from Eclipse plugin
func (e *GitHubProtocolExtractor) extractEclipseProtocol(sourceDir string) (string, error) {
	// Look for protocol version in Java files and manifest
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)PROTOCOL_VERSION\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)protocolVersion\s*=\s*"?(\d+)"?`),
		regexp.MustCompile(`(?m)requiredProtocolVersion["\s:=]+(\d+)`),
	}
	var protocolVersion string

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
					protocolVersion = string(matches[1])
					return errStopWalk
				}
			}
		}
		return nil
	})

	if err != nil && !errors.Is(err, errStopWalk) {
		return "", err
	}

	if protocolVersion == "" {
		return "", fmt.Errorf("protocol version not found in Eclipse plugin")
	}

	return protocolVersion, nil
}

// extractEclipseSemanticVersion extracts semantic version from Eclipse plugin MANIFEST.MF
func (e *GitHubProtocolExtractor) extractEclipseSemanticVersion(sourceDir string) string {
	var semanticVersion string
	// Pattern to match Bundle-Version in MANIFEST.MF (excluding .identifier suffix)
	versionPattern := regexp.MustCompile(`(?m)Bundle-Version:\s*(\d+\.\d+\.\d+)(?:\.identifier)?`)

	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		if strings.HasSuffix(path, "MANIFEST.MF") {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil // Continue walking
			}

			matches := versionPattern.FindSubmatch(content)
			if len(matches) > 1 {
				semanticVersion = string(matches[1])
				return errStopWalk
			}
		}
		return nil
	})

	if err != nil && !errors.Is(err, errStopWalk) {
		return ""
	}

	return semanticVersion
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

		// Prevent path traversal attacks (Zip Slip)
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry is trying to escape destination directory: %s", header.Name)
		}

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

			_, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}

	return nil
}
