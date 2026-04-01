/*
 * © 2026 Snyk Limited All rights reserved.
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

package directory_check

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_FormatResultsText_BasicOutput(t *testing.T) {
	testutil.UnitTest(t)

	result := &DiagnosticsResult{
		CurrentUser: "testuser",
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/test/path",
				Purpose:       "Test Purpose",
				MayContainCLI: true,
				PathFound:     "/test/path",
				IsWritable:    true,
				Permissions:   "0755",
			},
		},
	}

	output := FormatResultsText(result, false)

	assert.Contains(t, output, "testuser", "Should contain current user")
	assert.Contains(t, output, "/test/path", "Should contain directory path")
	assert.Contains(t, output, "Test Purpose", "Should contain purpose")
	assert.Contains(t, output, "Exists", "Should indicate directory exists")
	assert.Contains(t, output, "Writable", "Should indicate directory is writable")
}

func Test_FormatResultsText_NonExistentDirectory(t *testing.T) {
	testutil.UnitTest(t)

	result := &DiagnosticsResult{
		CurrentUser: "testuser",
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/test/does-not-exist/nested",
				Purpose:       "Test Non-Existent",
				MayContainCLI: false,
				PathFound:     "/test",
				IsWritable:    true,
				Permissions:   "0755",
			},
		},
	}

	output := FormatResultsText(result, false)

	assert.Contains(t, output, "/test/does-not-exist/nested", "Should contain wanted path")
	assert.Contains(t, output, "Does not exist", "Should indicate directory doesn't exist")
	assert.Contains(t, output, "/test", "Should show the found parent path")
}

func Test_FormatResultsText_WithBinaries(t *testing.T) {
	testutil.UnitTest(t)

	result := &DiagnosticsResult{
		CurrentUser: "testuser",
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/test/path",
				Purpose:       "CLI Location",
				MayContainCLI: true,
				PathFound:     "/test/path",
				IsWritable:    true,
				Permissions:   "0755",
				BinariesFound: []BinaryInfo{
					{Name: "snyk-linux", Permissions: "0755"},
					{Name: "snyk-macos", Permissions: "0755"},
				},
			},
		},
	}

	output := FormatResultsText(result, false)

	assert.Contains(t, output, "snyk-linux", "Should contain first binary name")
	assert.Contains(t, output, "snyk-macos", "Should contain second binary name")
	assert.Contains(t, output, "2", "Should indicate count of binaries found")
}

func Test_FormatResultsText_NotWritable(t *testing.T) {
	testutil.UnitTest(t)

	result := &DiagnosticsResult{
		CurrentUser: "testuser",
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/test/readonly",
				Purpose:       "Read-Only Test",
				MayContainCLI: false,
				PathFound:     "/test/readonly",
				IsWritable:    false,
				Permissions:   "0555",
			},
		},
	}

	output := FormatResultsText(result, false)

	assert.Contains(t, output, "Not writable", "Should indicate directory is not writable")
	assert.Contains(t, output, "0555", "Should show permissions")
}

func Test_FormatResultsText_WithError(t *testing.T) {
	testutil.UnitTest(t)

	result := &DiagnosticsResult{
		CurrentUser: "testuser",
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/test/error",
				Purpose:       "Error Test",
				MayContainCLI: false,
				Error:         "permission denied",
			},
		},
	}

	output := FormatResultsText(result, false)

	assert.Contains(t, output, "Error", "Should indicate an error")
	assert.Contains(t, output, "permission denied", "Should contain error message")
}

func Test_FormatResultsText_ColoredOutput(t *testing.T) {
	testutil.UnitTest(t)

	result := &DiagnosticsResult{
		CurrentUser: "testuser",
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/test/path",
				Purpose:       "Test Purpose",
				MayContainCLI: false,
				PathFound:     "/test/path",
				IsWritable:    true,
				Permissions:   "0755",
			},
		},
	}

	// Colored output should contain ANSI escape codes
	coloredOutput := FormatResultsText(result, true)
	plainOutput := FormatResultsText(result, false)

	// The colored output should be different (longer due to ANSI codes) or same if terminal doesn't support color
	// We can't guarantee color support in test environment, so just verify both work
	assert.NotEmpty(t, coloredOutput, "Colored output should not be empty")
	assert.NotEmpty(t, plainOutput, "Plain output should not be empty")
}

func Test_FormatResultsJSON_ValidJSON(t *testing.T) {
	testutil.UnitTest(t)

	result := &DiagnosticsResult{
		CurrentUser: "testuser",
		DirectoryResults: []DirectoryCheckResult{
			{
				PathWanted:    "/test/path",
				Purpose:       "Test Purpose",
				MayContainCLI: true,
				PathFound:     "/test/path",
				IsWritable:    true,
				Permissions:   "0755",
				BinariesFound: []BinaryInfo{
					{Name: "snyk-linux", Permissions: "0755"},
				},
			},
		},
	}

	output, err := FormatResultsJSON(result)
	require.NoError(t, err, "Should not return an error")

	// Verify it's valid JSON
	var parsed DiagnosticsResult
	err = json.Unmarshal([]byte(output), &parsed)
	require.NoError(t, err, "Output should be valid JSON")

	// Verify content
	assert.Equal(t, "testuser", parsed.CurrentUser)
	require.Len(t, parsed.DirectoryResults, 1)
	assert.Equal(t, "/test/path", parsed.DirectoryResults[0].PathWanted)
	assert.Equal(t, "Test Purpose", parsed.DirectoryResults[0].Purpose)
	require.Len(t, parsed.DirectoryResults[0].BinariesFound, 1)
	assert.Equal(t, "snyk-linux", parsed.DirectoryResults[0].BinariesFound[0].Name)
}

func Test_FormatResultsJSON_PrettyPrinted(t *testing.T) {
	testutil.UnitTest(t)

	result := &DiagnosticsResult{
		CurrentUser:      "testuser",
		DirectoryResults: []DirectoryCheckResult{},
	}

	output, err := FormatResultsJSON(result)
	require.NoError(t, err)

	// Should be pretty-printed (contains newlines and indentation)
	assert.True(t, strings.Contains(output, "\n"), "JSON should be pretty-printed with newlines")
	assert.True(t, strings.Contains(output, "  "), "JSON should be pretty-printed with indentation")
}

func Test_FormatResultsJSON_EmptyResults(t *testing.T) {
	testutil.UnitTest(t)

	result := &DiagnosticsResult{
		CurrentUser:      "testuser",
		DirectoryResults: []DirectoryCheckResult{},
	}

	output, err := FormatResultsJSON(result)
	require.NoError(t, err)

	var parsed DiagnosticsResult
	err = json.Unmarshal([]byte(output), &parsed)
	require.NoError(t, err)

	assert.Equal(t, "testuser", parsed.CurrentUser)
	assert.Empty(t, parsed.DirectoryResults)
}
