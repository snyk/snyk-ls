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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeGitURL(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "HTTPS URL with .git suffix",
			input:    "https://github.com/snyk/ldx-sync.git",
			expected: "https://github.com/snyk/ldx-sync",
		},
		{
			name:     "HTTPS URL without .git suffix",
			input:    "https://github.com/snyk/ldx-sync",
			expected: "https://github.com/snyk/ldx-sync",
		},
		{
			name:     "SSH URL with .git suffix",
			input:    "git@github.com:snyk/ldx-sync.git",
			expected: "https://github.com/snyk/ldx-sync",
		},
		{
			name:     "SSH URL without .git suffix",
			input:    "git@github.com:snyk/ldx-sync",
			expected: "https://github.com/snyk/ldx-sync",
		},
		{
			name:     "HTTP URL",
			input:    "http://github.com/snyk/ldx-sync",
			expected: "http://github.com/snyk/ldx-sync",
		},
		{
			name:     "empty URL",
			input:    "",
			expected: "",
		},
		{
			name:     "git protocol URL",
			input:    "git://github.com/user/repo.git",
			expected: "git://github.com/user/repo",
		},
		{
			name:     "URL with port",
			input:    "https://gitlab.com:8080/user/repo.git",
			expected: "https://gitlab.com:8080/user/repo",
		},
		{
			name:     "URL with path segments",
			input:    "https://github.com/org/team/repo.git",
			expected: "https://github.com/org/team/repo",
		},
		{
			name:     "SSH with port strips userinfo",
			input:    "ssh://git@github.com:22/user/repo.git",
			expected: "ssh://github.com:22/user/repo",
		},
		{
			name:     "SSH URL with different host",
			input:    "git@gitlab.com:user/repo.git",
			expected: "https://gitlab.com/user/repo",
		},
		{
			name:     "URL with query parameters",
			input:    "https://github.com/user/repo?ref=main",
			expected: "https://github.com/user/repo?ref=main",
		},
		{
			name:     "URL with fragment",
			input:    "https://github.com/user/repo#readme",
			expected: "https://github.com/user/repo#readme",
		},
		{
			name:     "Mixed case URL",
			input:    "https://GitHub.com/User/Repo.git",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "SCP-style URL with deploy@ prefix",
			input:    "deploy@gitlab.com:org/repo.git",
			expected: "https://gitlab.com/org/repo",
		},
		{
			name:     "SCP-style URL without user prefix",
			input:    "gitlab.example.com:group/repo.git",
			expected: "https://gitlab.example.com/group/repo",
		},
		{
			name:     "SCP-style SSH with port (two colons)",
			input:    "git@git.company.com:2222:team/project.git",
			expected: "https://git.company.com/team/project",
		},
		{
			name:     "URL without scheme becomes HTTPS",
			input:    "github.com/user/repo.git",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "HTTPS URL with credentials strips userinfo",
			input:    "https://user:token@github.com/snyk/repo.git",
			expected: "https://github.com/snyk/repo",
		},
		{
			name:     "HTTP URL with credentials strips userinfo",
			input:    "http://oauth2:secrettoken@gitlab.com/org/project.git",
			expected: "http://gitlab.com/org/project",
		},
		{
			name:     "SSH URL with credentials strips userinfo",
			input:    "ssh://git@github.com/user/repo.git",
			expected: "ssh://github.com/user/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeGitURL(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
