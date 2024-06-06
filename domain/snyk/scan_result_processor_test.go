/*
 * © 2022 Snyk Limited All rights reserved.
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

package snyk

import (
	"reflect"
	"testing"
)

func TestUpdateSeverityCount(t *testing.T) {
	tests := []struct {
		name     string
		initial  SeverityIssueCounts
		issue    Issue
		expected SeverityIssueCounts
	}{
		{
			name:    "Add new Critical issue",
			initial: make(SeverityIssueCounts),
			issue: Issue{
				Severity: Critical,
			},
			expected: SeverityIssueCounts{
				Critical: {Total: 1, Ignored: 0, Open: 1},
			},
		},
		{
			name: "Add ignored High issue",
			initial: SeverityIssueCounts{
				High: {Total: 1, Ignored: 1, Open: 0},
			},
			issue: Issue{
				Severity:  High,
				IsIgnored: true,
			},
			expected: SeverityIssueCounts{
				High: {Total: 2, Ignored: 2, Open: 0},
			},
		},
		{
			name: "Add new Medium issue",
			initial: SeverityIssueCounts{
				Medium: {Total: 2, Ignored: 1, Open: 1},
			},
			issue: Issue{
				Severity: Medium,
			},
			expected: SeverityIssueCounts{
				Medium: {Total: 3, Ignored: 1, Open: 2},
			},
		},
		{
			name:    "Add new Low issue",
			initial: make(SeverityIssueCounts),
			issue: Issue{
				Severity: Low,
			},
			expected: SeverityIssueCounts{
				Low: {Total: 1, Ignored: 0, Open: 1},
			},
		},
	}

	for _, testStruct := range tests {
		t.Run(testStruct.name, func(t *testing.T) {
			// Arrange
			initial := testStruct.initial
			issue := testStruct.issue

			// Act
			updateSeverityCount(initial, issue)

			// Assert
			if !reflect.DeepEqual(initial, testStruct.expected) {
				t.Errorf("updateSeverityCount() = %v, expects %v", initial, testStruct.expected)
			}
		})
	}
}

func TestGetSeverityIssueCounts(t *testing.T) {
	tests := []struct {
		name     string
		scanData ScanData
		expected SeverityIssueCounts
	}{
		{
			name: "Mixed issues",
			scanData: ScanData{
				Issues: []Issue{
					{Severity: Critical, IsIgnored: false},
					{Severity: Critical, IsIgnored: true},
					{Severity: High, IsIgnored: false},
					{Severity: Medium, IsIgnored: true},
					{Severity: Medium, IsIgnored: false},
					{Severity: Low, IsIgnored: false},
				},
			},
			expected: SeverityIssueCounts{
				Critical: {Total: 2, Ignored: 1, Open: 1},
				High:     {Total: 1, Ignored: 0, Open: 1},
				Medium:   {Total: 2, Ignored: 1, Open: 1},
				Low:      {Total: 1, Ignored: 0, Open: 1},
			},
		},
	}

	for _, testStruct := range tests {
		t.Run(testStruct.name, func(t *testing.T) {
			// Arrange
			scanData := testStruct.scanData

			// Act
			result := scanData.GetSeverityIssueCounts()

			// Assert
			if !reflect.DeepEqual(result, testStruct.expected) {
				t.Errorf("GetSeverityIssueCounts() = %v, expects %v", result, testStruct.expected)
			}
		})
	}
}
