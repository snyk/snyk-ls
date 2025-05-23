/*
 * © 2024 Snyk Limited
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
	"sort"
	"strings"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

func CalculateFingerprintFromAdditionalData(issue types.Issue) string {
	var fingerprint string
	var dependencyChain string
	switch additionalData := issue.GetAdditionalData().(type) {
	case snyk.OssIssueData:
		// first element is directory name. It should not be considered for the fingerprint
		if len(additionalData.From) > 1 {
			dependencyChain = normalizeArray(additionalData.From[1:])
		} else {
			dependencyChain = normalizeArray(additionalData.From)
		}
		// Fingerprint for OSS Issues is: name@version@fromArrayHash
		fingerprint = fmt.Sprintf("%s|%s|%s|%s", additionalData.PackageName, additionalData.Version, dependencyChain, issue.GetRuleID())
	case snyk.IaCIssueData:
		// No need to normalize and change order of the array for IaC since order matters
		dependencyChain = strings.Join(additionalData.Path, "|")
		fingerprint = fmt.Sprintf("%s|%s", issue.GetRuleID(), dependencyChain)
	default:
		return ""
	}

	hash := sha256.Sum256([]byte(fingerprint))
	return fmt.Sprintf("%x", hash)
}

func normalizeArray(array []string) string {
	normalized := make([]string, len(array))
	// Normalize spaces
	for i, item := range array {
		normalized[i] = strings.Join(strings.Fields(item), "|")
	}
	sort.Strings(normalized)

	joinedArray := strings.Join(normalized, "|")
	return joinedArray
}
