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
	"strings"
	"testing"
	"time"
)

func TestGenerateMatrix(t *testing.T) {
	// Create test releases
	releases := []Release{
		{
			Repository:      "vscode-extension",
			PluginName:      "VSCode",
			Version:         "v2.2.0",
			Tag:             "v2.2.0",
			ReleaseDate:     time.Date(2025, 5, 16, 0, 0, 0, 0, time.UTC),
			ProtocolVersion: "20",
			CLIVersion:      "v1.1297.0",
		},
		{
			Repository:      "snyk-intellij-plugin",
			PluginName:      "IntelliJ",
			Version:         "v3.4.2",
			Tag:             "v3.4.2",
			ReleaseDate:     time.Date(2025, 5, 15, 0, 0, 0, 0, time.UTC),
			ProtocolVersion: "20",
			CLIVersion:      "v1.1297.0",
		},
	}

	// Generate matrix
	matrix, err := generateMatrix(releases)
	if err != nil {
		t.Fatalf("generateMatrix failed: %v", err)
	}

	// Verify output contains expected content
	expectedContent := []string{
		"# IDE Plugin Compatibility Matrix",
		"| Release Date | IDE Plugin | Minimum CLI Version |",
		"| 2025-05-16 | VSCode v2.2.0 | v1.1297.0 |",
		"| 2025-05-15 | IntelliJ v3.4.2 | v1.1297.0 |",
	}

	for _, expected := range expectedContent {
		if !strings.Contains(matrix, expected) {
			t.Errorf("Matrix does not contain expected content: %s", expected)
		}
	}
}

func TestGetIDEPlugins(t *testing.T) {
	plugins := GetIDEPlugins()

	if len(plugins) != 4 {
		t.Errorf("Expected 4 IDE plugins, got %d", len(plugins))
	}

	expectedRepos := map[string]string{
		"vscode-extension":          "VSCode",
		"snyk-intellij-plugin":      "IntelliJ",
		"snyk-visual-studio-plugin": "Visual Studio",
		"snyk-eclipse-plugin":       "Eclipse",
	}

	for _, plugin := range plugins {
		expectedName, ok := expectedRepos[plugin.Repo]
		if !ok {
			t.Errorf("Unexpected repository: %s", plugin.Repo)
		}
		if plugin.DisplayName != expectedName {
			t.Errorf("Expected display name %s for repo %s, got %s",
				expectedName, plugin.Repo, plugin.DisplayName)
		}
	}
}

func TestCacheKeyGeneration(t *testing.T) {
	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{
			name:     "CLI version cache key",
			fn:       func() string { return GetCLIVersionCacheKey("20") },
			expected: "cli-version-stable-20",
		},
		{
			name:     "Release cache key",
			fn:       func() string { return GetReleaseCacheKey("vscode-extension", "v2.2.0") },
			expected: "release-vscode-extension-v2.2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
