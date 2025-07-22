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
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

func main() {
	var (
		outputFile = flag.String("output", "compatibility-matrix.md", "Output file path")
		cachePath  = flag.String("cache", ".cache/compatibility-matrix", "Cache directory path")
		months     = flag.Int("months", 12, "Number of months to look back for releases")
		dryRun     = flag.Bool("dry-run", false, "Print output to stdout instead of writing to file")
	)
	flag.Parse()

	// Initialize cache
	cache := NewCache(*cachePath)

	// Calculate cutoff date
	cutoffDate := time.Now().AddDate(0, -(*months), 0)

	// Analyze CLI releases to build protocol version mapping
	log.Println("Analyzing CLI releases...")
	cliAnalyzer := NewCLIAnalyzer(cache, filepath.Join(*cachePath, "repos"))
	protocolToCLI, err := cliAnalyzer.AnalyzeCLIReleases(*months)
	if err != nil {
		log.Fatalf("Failed to analyze CLI releases: %v", err)
	}
	log.Printf("Found %d protocol versions with CLI mappings", len(protocolToCLI))

	// Fetch releases from all IDE plugins
	log.Println("Fetching releases from IDE plugin repositories...")
	releases, err := fetchAllReleases(cutoffDate, cache, protocolToCLI)
	if err != nil {
		log.Fatalf("Failed to fetch releases: %v", err)
	}

	// Generate compatibility matrix
	log.Printf("Generating compatibility matrix for %d releases...", len(releases))
	matrix, err := generateMatrix(releases)
	if err != nil {
		log.Fatalf("Failed to generate matrix: %v", err)
	}

	// Write output
	if *dryRun {
		_, _ = fmt.Fprintln(os.Stdout, matrix)
	} else {
		if err := os.WriteFile(*outputFile, []byte(matrix), 0644); err != nil {
			log.Fatalf("Failed to write output file: %v", err)
		}
		log.Printf("Compatibility matrix written to %s", *outputFile)
	}
}

// Release represents an IDE plugin release
type Release struct {
	Repository      string
	PluginName      string
	Version         string
	SemanticVersion string // For Eclipse: semantic version from MANIFEST.MF
	ReleaseDate     time.Time
	ProtocolVersion string
	CLIVersionRange string       // Range of compatible CLI versions
	CompatibleCLIs  []CLIRelease // Full list of compatible CLI releases
}

// fetchAllReleases fetches releases from all monitored IDE plugin repositories
func fetchAllReleases(cutoffDate time.Time, cache *Cache, protocolToCLI map[string][]CLIRelease) ([]Release, error) {
	plugins := GetIDEPlugins()
	githubClient := NewGitHubClient()
	protocolExtractor := NewProtocolExtractor(cache)

	var allReleases []Release
	var allErrors []error
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process each plugin concurrently
	for _, plugin := range plugins {
		wg.Add(1)
		go func(p IDEPlugin) {
			defer wg.Done()

			log.Printf("Fetching releases for %s...", p.DisplayName)

			// Fetch GitHub releases
			ghReleases, err := githubClient.FetchReleases(p.Owner, p.Repo, cutoffDate)
			if err != nil {
				mu.Lock()
				allErrors = append(allErrors, fmt.Errorf("failed to fetch releases for %s: %w", p.DisplayName, err))
				mu.Unlock()
				log.Printf("Error fetching releases for %s: %v", p.DisplayName, err)
				return
			}

			// Process each release
			for _, ghRelease := range ghReleases {
				release := Release{
					Repository:  p.Repo,
					PluginName:  p.DisplayName,
					Version:     ghRelease.TagName,
					ReleaseDate: ghRelease.PublishedAt,
				}

				// Extract protocol version
				versionInfo, err := protocolExtractor.ExtractProtocolVersion(p, ghRelease.TagName)
				if err != nil {
					log.Printf("Warning: Failed to extract protocol version for %s %s: %v",
						p.DisplayName, ghRelease.TagName, err)
					continue
				}
				release.ProtocolVersion = versionInfo.ProtocolVersion
				release.SemanticVersion = versionInfo.SemanticVersion

				// Get compatible CLI versions from mapping
				compatibleCLIs, ok := protocolToCLI[versionInfo.ProtocolVersion]
				if !ok || len(compatibleCLIs) == 0 {
					log.Printf("Warning: No compatible CLI versions found for protocol %s",
						versionInfo.ProtocolVersion)
					continue
				}
				release.CompatibleCLIs = compatibleCLIs
				release.CLIVersionRange = FormatCLIRange(compatibleCLIs)

				mu.Lock()
				allReleases = append(allReleases, release)
				mu.Unlock()
			}
		}(plugin)
	}

	wg.Wait()

	// Check if any errors occurred
	if len(allErrors) > 0 {
		return nil, fmt.Errorf("failed to fetch releases from %d plugin(s): %v", len(allErrors), allErrors)
	}

	// Sort by release date (descending)
	sort.Slice(allReleases, func(i, j int) bool {
		return allReleases[i].ReleaseDate.After(allReleases[j].ReleaseDate)
	})

	return allReleases, nil
}

// generateMatrix generates the markdown compatibility matrix
func generateMatrix(releases []Release) (string, error) {
	var sb strings.Builder

	// Write header
	sb.WriteString("# IDE Plugin Compatibility Matrix\n\n")
	sb.WriteString("This matrix shows the compatible CLI version range for each IDE plugin version ")
	sb.WriteString("released in the past 12 months.\n\n")

	// Write table header
	sb.WriteString("| Release Date | IDE Plugin | Compatible CLIs |\n")
	sb.WriteString("|--------------|------------|-----------------|\n")

	// Write table rows
	for _, release := range releases {
		date := release.ReleaseDate.Format("2006-01-02")

		// Format plugin name differently for Eclipse
		var plugin string
		if release.PluginName == "Eclipse" && release.SemanticVersion != "" {
			// Eclipse format: Eclipse v3.3 (v20250717.103834)
			plugin = fmt.Sprintf("Eclipse v%s (%s)", release.SemanticVersion, release.Version)
		} else {
			// Regular format for other plugins
			plugin = fmt.Sprintf("%s %s", release.PluginName, release.Version)
		}

		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
			date, plugin, release.CLIVersionRange))
	}

	// Add footer
	sb.WriteString("\n## Notes\n\n")
	sb.WriteString("- This matrix is automatically generated and updated daily\n")
	sb.WriteString("- Only stable releases are included (pre-releases and drafts are excluded)\n")
	sb.WriteString("- CLI versions shown are from the stable channel\n")

	return sb.String(), nil
}
