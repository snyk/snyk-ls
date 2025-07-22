// Copyright 2025 Snyk Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// CLIRelease represents a CLI release with its protocol version
type CLIRelease struct {
	Version         string
	ReleaseDate     time.Time
	ProtocolVersion string
}

// CLIAnalyzer analyzes CLI releases to extract protocol versions
type CLIAnalyzer struct {
	cache      *Cache
	workDir    string
	cliRepoDir string
	lsRepoDir  string
}

// NewCLIAnalyzer creates a new CLI analyzer
func NewCLIAnalyzer(cache *Cache, workDir string) *CLIAnalyzer {
	return &CLIAnalyzer{
		cache:   cache,
		workDir: workDir,
	}
}

// AnalyzeCLIReleases analyzes CLI releases and returns a map of protocol version to CLI versions
func (a *CLIAnalyzer) AnalyzeCLIReleases(months int) (map[string][]CLIRelease, error) {
	// Clone repositories
	if err := a.cloneRepositories(); err != nil {
		return nil, fmt.Errorf("failed to clone repositories: %w", err)
	}

	// Get CLI releases
	releases, err := a.getCLIReleases(months)
	if err != nil {
		return nil, fmt.Errorf("failed to get CLI releases: %w", err)
	}

	// Extract protocol versions for each release
	for i := range releases {
		protocolVersion, err := a.extractProtocolVersion(&releases[i])
		if err != nil {
			log.Printf("Warning: Failed to extract protocol version for CLI %s: %v", releases[i].Version, err)
			continue
		}
		releases[i].ProtocolVersion = protocolVersion
	}

	// Group by protocol version
	protocolToCLI := make(map[string][]CLIRelease)
	for _, release := range releases {
		if release.ProtocolVersion != "" {
			protocolToCLI[release.ProtocolVersion] = append(protocolToCLI[release.ProtocolVersion], release)
		}
	}

	// Sort CLI versions within each protocol version group
	for protocol := range protocolToCLI {
		sort.Slice(protocolToCLI[protocol], func(i, j int) bool {
			return protocolToCLI[protocol][i].Version < protocolToCLI[protocol][j].Version
		})
	}

	return protocolToCLI, nil
}

// cloneRepositories clones the CLI and LS repositories
func (a *CLIAnalyzer) cloneRepositories() error {
	// Create work directory
	if err := os.MkdirAll(a.workDir, 0755); err != nil {
		return err
	}

	// Clone CLI repo if not exists
	a.cliRepoDir = filepath.Join(a.workDir, "cli")
	if _, err := os.Stat(a.cliRepoDir); os.IsNotExist(err) {
		log.Println("Cloning Snyk CLI repository...")
		cmd := exec.Command("git", "clone", "--bare", "https://github.com/snyk/cli.git", a.cliRepoDir)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to clone CLI repo: %w\n%s", err, output)
		}
	} else {
		// Update existing repo
		log.Println("Updating Snyk CLI repository...")
		cmd := exec.Command("git", "fetch", "--all", "--tags")
		cmd.Dir = a.cliRepoDir
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to update CLI repo: %w\n%s", err, output)
		}
	}

	// Clone LS repo if not exists
	a.lsRepoDir = filepath.Join(a.workDir, "snyk-ls")
	if _, err := os.Stat(a.lsRepoDir); os.IsNotExist(err) {
		log.Println("Cloning Snyk LS repository...")
		cmd := exec.Command("git", "clone", "--bare", "https://github.com/snyk/snyk-ls.git", a.lsRepoDir)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to clone LS repo: %w\n%s", err, output)
		}
	} else {
		// Update existing repo
		log.Println("Updating Snyk LS repository...")
		cmd := exec.Command("git", "fetch", "--all", "--tags")
		cmd.Dir = a.lsRepoDir
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to update LS repo: %w\n%s", err, output)
		}
	}

	return nil
}

// getCLIReleases gets CLI releases from the past N months
func (a *CLIAnalyzer) getCLIReleases(months int) ([]CLIRelease, error) {
	cutoffDate := time.Now().AddDate(0, -months, 0)

	// Get all tags
	cmd := exec.Command("git", "tag", "-l", "v*", "--sort=-version:refname")
	cmd.Dir = a.cliRepoDir
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get tags: %w", err)
	}

	var releases []CLIRelease
	tags := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, tag := range tags {
		if tag == "" {
			continue
		}

		// Get tag date
		cmd := exec.Command("git", "log", "-1", "--format=%ai", fmt.Sprintf("refs/tags/%s", tag))
		cmd.Dir = a.cliRepoDir
		dateOutput, err := cmd.Output()
		if err != nil {
			log.Printf("Warning: Failed to get date for tag %s: %v", tag, err)
			continue
		}

		releaseDate, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(string(dateOutput)))
		if err != nil {
			log.Printf("Warning: Failed to parse date for tag %s: %v", tag, err)
			continue
		}

		if releaseDate.Before(cutoffDate) {
			break // Tags are sorted by version, so we can stop here
		}

		releases = append(releases, CLIRelease{
			Version:     tag,
			ReleaseDate: releaseDate,
		})
	}

	return releases, nil
}

// extractProtocolVersion extracts the protocol version for a CLI release
func (a *CLIAnalyzer) extractProtocolVersion(release *CLIRelease) (string, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("cli-protocol:%s", release.Version)
	var cachedVersion string
	if found, err := a.cache.Get(cacheKey, &cachedVersion); found && err == nil {
		return cachedVersion, nil
	}

	// Get go.mod content for the release
	// The Snyk CLI has go.mod in the cliv2 directory
	cmd := exec.Command("git", "show", fmt.Sprintf("refs/tags/%s:cliv2/go.mod", release.Version))
	cmd.Dir = a.cliRepoDir
	goModContent, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get go.mod for %s: %w", release.Version, err)
	}

	// Extract snyk-ls commit hash from go.mod
	lsCommit, err := a.extractLSCommit(string(goModContent))
	if err != nil {
		return "", fmt.Errorf("failed to extract LS commit: %w", err)
	}

	// Get protocol version from LS commit
	protocolVersion, err := a.getProtocolVersionFromCommit(lsCommit)
	if err != nil {
		return "", fmt.Errorf("failed to get protocol version from commit %s: %w", lsCommit, err)
	}

	// Cache the result
	if err := a.cache.Set(cacheKey, protocolVersion, 30*24*time.Hour); err != nil {
		log.Printf("Warning: failed to cache protocol version for %s: %v", release.Version, err)
	}

	return protocolVersion, nil
}

// extractLSCommit extracts the snyk-ls commit hash from go.mod content
func (a *CLIAnalyzer) extractLSCommit(goModContent string) (string, error) {
	// Look for snyk-ls dependency
	// Example: github.com/snyk/snyk-ls v0.0.0-20240312164628-a34294ea7208
	pattern := regexp.MustCompile(`github\.com/snyk/snyk-ls\s+v\d+\.\d+\.\d+-(\d{14}-[a-f0-9]{12})`)
	matches := pattern.FindStringSubmatch(goModContent)
	if len(matches) < 2 {
		// Try another pattern for direct commit references
		pattern = regexp.MustCompile(`github\.com/snyk/snyk-ls\s+([a-f0-9]{40})`)
		matches = pattern.FindStringSubmatch(goModContent)
		if len(matches) < 2 {
			return "", fmt.Errorf("snyk-ls dependency not found in go.mod")
		}
	}

	// Extract commit hash from version
	commit := matches[1]
	if strings.Contains(commit, "-") {
		// Extract hash from timestamp-hash format
		parts := strings.Split(commit, "-")
		if len(parts) == 2 {
			commit = parts[1]
		}
	}

	return commit, nil
}

// getProtocolVersionFromCommit gets the protocol version from a specific LS commit
func (a *CLIAnalyzer) getProtocolVersionFromCommit(commit string) (string, error) {
	// Try to get .goreleaser.yaml content at the specific commit
	var content []byte
	var err error

	// Try with full commit first
	cmd := exec.Command("git", "show", fmt.Sprintf("%s:.goreleaser.yaml", commit))
	cmd.Dir = a.lsRepoDir
	content, err = cmd.Output()

	// If that fails, try with abbreviated commit
	if err != nil && len(commit) > 7 {
		shortCommit := commit[:7]
		cmd = exec.Command("git", "show", fmt.Sprintf("%s:.goreleaser.yaml", shortCommit))
		cmd.Dir = a.lsRepoDir
		content, err = cmd.Output()
	}

	// If .goreleaser.yaml doesn't exist, try internal/types/lsp_protocol_version.go
	if err != nil {
		cmd = exec.Command("git", "show", fmt.Sprintf("%s:internal/types/lsp_protocol_version.go", commit))
		cmd.Dir = a.lsRepoDir
		content, err = cmd.Output()
		if err != nil && len(commit) > 7 {
			shortCommit := commit[:7]
			cmd = exec.Command("git", "show", fmt.Sprintf("%s:internal/types/lsp_protocol_version.go", shortCommit))
			cmd.Dir = a.lsRepoDir
			content, err = cmd.Output()
		}
		if err != nil {
			return "", fmt.Errorf("failed to get protocol version file: %w", err)
		}

		// Extract from lsp_protocol_version.go
		pattern := regexp.MustCompile(`LspProtocolVersion\s*=\s*(\d+)`)
		matches := pattern.FindStringSubmatch(string(content))
		if len(matches) < 2 {
			return "", fmt.Errorf("protocol version not found in lsp_protocol_version.go")
		}
		return matches[1], nil
	}

	// Extract protocol version from .goreleaser.yaml
	pattern := regexp.MustCompile(`LS_PROTOCOL_VERSION\s*=\s*(\d+)`)
	matches := pattern.FindStringSubmatch(string(content))
	if len(matches) < 2 {
		return "", fmt.Errorf("protocol version not found in .goreleaser.yaml")
	}

	return matches[1], nil
}

// FormatCLIRange formats a range of CLI versions
func FormatCLIRange(cliReleases []CLIRelease) string {
	if len(cliReleases) == 0 {
		return "N/A"
	}
	if len(cliReleases) == 1 {
		return cliReleases[0].Version
	}

	// Get min and max versions
	minVersion := cliReleases[0].Version
	maxVersion := cliReleases[len(cliReleases)-1].Version

	return fmt.Sprintf("%s - %s", minVersion, maxVersion)
}
