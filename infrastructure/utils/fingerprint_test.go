/*
 * © 2025 Snyk Limited
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

package utils

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
)

func TestCalculateFingerprintFromAdditionalData_OssIssueData(t *testing.T) {
	// Test with multiple "from" elements
	issue := snyk.Issue{
		AdditionalData: snyk.OssIssueData{PackageName: "pkg",
			Version: "1.0.0",
			From:    []string{"dir", "dep1", "dep2"},
		},
	}
	expectedHash := sha256.Sum256([]byte("pkg|1.0.0|dep1|dep2"))
	assert.Equal(t, fmt.Sprintf("%x", expectedHash), CalculateFingerprintFromAdditionalData(issue))

	// Test with single "from" element
	issue = snyk.Issue{
		AdditionalData: snyk.OssIssueData{PackageName: "pkg2",
			Version: "2.0.0",
			From:    []string{"dep1"},
		},
	}
	expectedHash = sha256.Sum256([]byte("pkg2|2.0.0|dep1"))
	assert.Equal(t, fmt.Sprintf("%x", expectedHash), CalculateFingerprintFromAdditionalData(issue))

	// Test with empty "from" element
	issue = snyk.Issue{
		AdditionalData: snyk.OssIssueData{PackageName: "pkg3",
			Version: "3.0.0",
			From:    []string{},
		},
	}
	expectedHash = sha256.Sum256([]byte("pkg3|3.0.0|"))
	assert.Equal(t, fmt.Sprintf("%x", expectedHash), CalculateFingerprintFromAdditionalData(issue))

	// Test with "from" containing spaces
	issue = snyk.Issue{
		AdditionalData: snyk.OssIssueData{PackageName: "pkg4",
			Version: "4.0.0",
			From:    []string{"dir", "dep1 with spaces", " dep2 with spaces "},
		},
	}
	expectedHash = sha256.Sum256([]byte("pkg4|4.0.0|dep1|with|spaces|dep2|with|spaces"))
	assert.Equal(t, fmt.Sprintf("%x", expectedHash), CalculateFingerprintFromAdditionalData(issue))
}

func TestCalculateFingerprintFromAdditionalData_IaCIssueData(t *testing.T) {
	issue := snyk.Issue{
		AdditionalData: snyk.IaCIssueData{Path: []string{"path1", "path2", "path3"}},
	}

	expectedHash := sha256.Sum256([]byte("path1|path2|path3"))
	assert.Equal(t, fmt.Sprintf("%x", expectedHash), CalculateFingerprintFromAdditionalData(issue))

	// Test with spaces in path
	issue = snyk.Issue{
		AdditionalData: snyk.IaCIssueData{Path: []string{"path1 with spaces", " path2 with spaces"}},
	}
	expectedHash = sha256.Sum256([]byte("path1 with spaces| path2 with spaces"))
	assert.Equal(t, fmt.Sprintf("%x", expectedHash), CalculateFingerprintFromAdditionalData(issue))
}

func TestNormalizeArray(t *testing.T) {
	array := []string{"item3", "item1", "item2 with spaces", " item4 with spaces "}
	expected := "item1|item2|with|spaces|item3|item4|with|spaces"
	assert.Equal(t, expected, normalizeArray(array))

	emptyArray := []string{}
	assert.Equal(t, "", normalizeArray(emptyArray))
}
