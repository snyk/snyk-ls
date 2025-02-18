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

	"github.com/snyk/snyk-ls/internal/types"
)

func TestUpdateSeverityCount(t *testing.T) {
	tests := []struct {
		name     string
		initial  types.SeverityIssueCounts
		issue    types.Issue
		expected types.SeverityIssueCounts
	}{{
		name:    "Add new Critical issue",
		initial: make(types.SeverityIssueCounts),
		issue: &Issue{
			Severity: types.Critical,
		},
		expected: types.SeverityIssueCounts{
			types.Critical: {Total: 1, Ignored: 0, Open: 1},
		},
	}, {
		name: "Add ignored High issue",
		initial: types.SeverityIssueCounts{
			types.High: {Total: 1, Ignored: 1, Open: 0},
		},
		issue: &Issue{
			Severity:  types.High,
			IsIgnored: true,
		},
		expected: types.SeverityIssueCounts{
			types.High: {Total: 2, Ignored: 2, Open: 0},
		},
	}, {
		name: "Add new Medium issue",
		initial: types.SeverityIssueCounts{
			types.Medium: {Total: 2, Ignored: 1, Open: 1},
		},
		issue: &Issue{
			Severity: types.Medium,
		},
		expected: types.SeverityIssueCounts{
			types.Medium: {Total: 3, Ignored: 1, Open: 2},
		},
	}, {
		name:    "Add new Low issue",
		initial: make(types.SeverityIssueCounts),
		issue: &Issue{
			Severity: types.Low,
		},
		expected: types.SeverityIssueCounts{
			types.Low: {Total: 1, Ignored: 0, Open: 1},
		}}}

	for _, testStruct := range tests {
		t.Run(testStruct.name, func(t *testing.T) {
			// Arrange
			initial := testStruct.initial
			issue := testStruct.issue

			// Act
			types.UpdateSeverityCount(initial, issue)

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
		scanData types.ScanData
		expected types.SeverityIssueCounts
	}{{
		name: "Mixed issues",
		scanData: types.ScanData{
			Issues: []types.Issue{
				&Issue{Severity: types.Critical, IsIgnored: false},
				&Issue{Severity: types.Critical, IsIgnored: true},
				&Issue{Severity: types.High, IsIgnored: false},
				&Issue{Severity: types.Medium, IsIgnored: true},
				&Issue{Severity: types.Medium, IsIgnored: false},
				&Issue{Severity: types.Low, IsIgnored: false},
			},
		},
		expected: types.SeverityIssueCounts{
			types.Critical: {Total: 2, Ignored: 1, Open: 1},
			types.High:     {Total: 1, Ignored: 0, Open: 1},
			types.Medium:   {Total: 2, Ignored: 1, Open: 1},
			types.Low:      {Total: 1, Ignored: 0, Open: 1},
		},
	}}

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
