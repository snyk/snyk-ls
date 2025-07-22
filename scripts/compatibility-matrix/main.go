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

	// Fetch releases from all IDE plugins
	log.Println("Fetching releases from IDE plugin repositories...")
	releases, err := fetchAllReleases(cutoffDate, cache)
	if err != nil {
		log.Fatalf("Failed to fetch releases: %v", err)
	}

	// Generate compatibility matrix
	log.Printf("Generating compatibility matrix for %d releases...", len(releases))
	matrix, err := generateMatrix(releases, cache)
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
	Tag             string
	ReleaseDate     time.Time
	ProtocolVersion string
	CLIVersion      string
}

// fetchAllReleases fetches releases from all monitored IDE plugin repositories
func fetchAllReleases(cutoffDate time.Time, cache *Cache) ([]Release, error) {
	plugins := GetIDEPlugins()
	githubClient := NewGitHubClient()
	protocolExtractor := NewProtocolExtractor(cache)
	cliMapper := NewCLIVersionMapper(cache)

	var allReleases []Release
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
				log.Printf("Error fetching releases for %s: %v", p.DisplayName, err)
				return
			}

			// Process each release
			for _, ghRelease := range ghReleases {
				release := Release{
					Repository:  p.Repo,
					PluginName:  p.DisplayName,
					Version:     ghRelease.TagName,
					Tag:         ghRelease.TagName,
					ReleaseDate: ghRelease.PublishedAt,
				}

				// Extract protocol version
				protocolVersion, err := protocolExtractor.ExtractProtocolVersion(p, ghRelease.TagName)
				if err != nil {
					log.Printf("Warning: Failed to extract protocol version for %s %s: %v",
						p.DisplayName, ghRelease.TagName, err)
					continue
				}
				release.ProtocolVersion = protocolVersion

				// Get CLI version
				cliVersion, err := cliMapper.GetCLIVersion(protocolVersion)
				if err != nil {
					log.Printf("Warning: Failed to get CLI version for protocol %s: %v",
						protocolVersion, err)
					continue
				}
				release.CLIVersion = cliVersion

				mu.Lock()
				allReleases = append(allReleases, release)
				mu.Unlock()
			}
		}(plugin)
	}

	wg.Wait()

	// Sort by release date (descending)
	sort.Slice(allReleases, func(i, j int) bool {
		return allReleases[i].ReleaseDate.After(allReleases[j].ReleaseDate)
	})

	return allReleases, nil
}

// generateMatrix generates the markdown compatibility matrix
func generateMatrix(releases []Release, cache *Cache) (string, error) {
	var sb strings.Builder

	// Write header
	sb.WriteString("# IDE Plugin Compatibility Matrix\n\n")
	sb.WriteString("This matrix shows the minimum CLI version required for each IDE plugin version ")
	sb.WriteString("released in the past 12 months.\n\n")
	sb.WriteString("Last updated: " + time.Now().UTC().Format("2006-01-02 15:04:05 UTC") + "\n\n")

	// Write table header
	sb.WriteString("| Release Date | IDE Plugin | Minimum CLI Version |\n")
	sb.WriteString("|--------------|------------|---------------------|\n")

	// Write table rows
	for _, release := range releases {
		date := release.ReleaseDate.Format("2006-01-02")
		plugin := fmt.Sprintf("%s %s", release.PluginName, release.Version)

		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
			date, plugin, release.CLIVersion))
	}

	// Add footer
	sb.WriteString("\n## Notes\n\n")
	sb.WriteString("- This matrix is automatically generated and updated daily\n")
	sb.WriteString("- Only stable releases are included (pre-releases and drafts are excluded)\n")
	sb.WriteString("- CLI versions shown are from the preview channel\n")

	return sb.String(), nil
}
