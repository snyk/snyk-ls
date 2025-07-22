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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
}

// GitHubClient handles GitHub API interactions
type GitHubClient struct {
	httpClient *http.Client
	token      string
}

// NewGitHubClient creates a new GitHub API client
func NewGitHubClient() *GitHubClient {
	return &GitHubClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		token: os.Getenv("GITHUB_TOKEN"),
	}
}

// FetchReleases fetches releases from a GitHub repository
func (g *GitHubClient) FetchReleases(owner, repo string, since time.Time) ([]GitHubRelease, error) {
	var allReleases []GitHubRelease
	page := 1
	perPage := 100

	for {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?page=%d&per_page=%d", owner, repo, page, perPage)

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Accept", "application/vnd.github.v3+json")
		if g.token != "" {
			req.Header.Set("Authorization", "token "+g.token)
		}

		resp, err := g.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return nil, fmt.Errorf("GitHub API error: %s (failed to read body: %v)", resp.Status, readErr)
			}
			return nil, fmt.Errorf("GitHub API error: %s - %s", resp.Status, string(body))
		}

		var releases []GitHubRelease
		if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
			return nil, err
		}

		// Filter releases by date and add to results
		for _, release := range releases {
			if release.Draft || release.Prerelease {
				continue
			}

			if release.PublishedAt.Before(since) {
				// Since releases are ordered by date, we can stop here
				return allReleases, nil
			}

			allReleases = append(allReleases, release)
		}

		// Check if there are more pages
		if len(releases) < perPage {
			break
		}

		page++
	}

	return allReleases, nil
}

// IDEPlugin represents an IDE plugin repository
type IDEPlugin struct {
	Owner       string
	Repo        string
	DisplayName string
}

// GetIDEPlugins returns the list of IDE plugins to monitor
func GetIDEPlugins() []IDEPlugin {
	return []IDEPlugin{
		{
			Owner:       "snyk",
			Repo:        "vscode-extension",
			DisplayName: "VSCode",
		},
		{
			Owner:       "snyk",
			Repo:        "snyk-intellij-plugin",
			DisplayName: "IntelliJ",
		},
		{
			Owner:       "snyk",
			Repo:        "snyk-visual-studio-plugin",
			DisplayName: "Visual Studio",
		},
		{
			Owner:       "snyk",
			Repo:        "snyk-eclipse-plugin",
			DisplayName: "Eclipse",
		},
	}
}
