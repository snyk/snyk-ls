/*
 * © 2026 Snyk Limited
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

package util

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	gitSuffix       = ".git"
	schemeSeparator = "://"
)

// NormalizeGitURL normalizes various Git URL formats to a consistent format.
// Returns a normalized URL with: scheme preserved (defaults to https), no credentials, lowercase host/path.
// Replicates the normalization logic from the LDX-Sync backend so that folder settings
// keyed by normalized URL in the API response can be matched from the raw git remote URL.
func NormalizeGitURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", nil
	}
	u, err := ParseGitURL(rawURL)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Path = strings.TrimSuffix(u.Path, gitSuffix)
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.ToLower(u.Path)
	return u.String(), nil
}

// ParseGitURL parses a Git URL and returns a sanitized url.URL with credentials stripped.
// Handles SCP-style URLs (git@host:path), URLs without schemes, and standard URLs.
func ParseGitURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(prepareURLForParsing(rawURL))
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	u.User = nil
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	return u, nil
}

func prepareURLForParsing(rawURL string) string {
	if isSCPStyleURL(rawURL) {
		return convertSCPToHTTPS(rawURL)
	}
	if !strings.Contains(rawURL, schemeSeparator) {
		return "https://" + rawURL
	}
	return rawURL
}

func isSCPStyleURL(rawURL string) bool {
	if strings.Contains(rawURL, schemeSeparator) {
		return false
	}
	hostPart := rawURL
	if atIdx := strings.Index(rawURL, "@"); atIdx != -1 {
		hostPart = rawURL[atIdx+1:]
	}
	colonIdx := strings.Index(hostPart, ":")
	return colonIdx != -1 && colonIdx < len(hostPart)-1
}

func convertSCPToHTTPS(rawURL string) string {
	hostAndPath := rawURL
	if atIdx := strings.Index(rawURL, "@"); atIdx != -1 {
		hostAndPath = rawURL[atIdx+1:]
	}
	colonCount := strings.Count(hostAndPath, ":")
	if colonCount >= 2 {
		parts := strings.SplitN(hostAndPath, ":", 3)
		if isNumericString(parts[1]) {
			return "https://" + parts[0] + "/" + parts[2]
		}
		return "https://" + parts[0] + "/" + parts[1] + ":" + parts[2]
	}
	return "https://" + strings.Replace(hostAndPath, ":", "/", 1)
}

func isNumericString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
