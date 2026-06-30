/*
 * © 2023 Snyk Limited
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

package command

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

//goland:noinspection GoRedundantConversion
func Test_getLearnLesson_Execute(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name      string
		eco       string
		rule      string
		cwes      string
		cves      string
		issueType types.IssueType
		expCWEs   []string
		expCVEs   []string
	}{
		{
			name:      "DependencyVulnerability",
			eco:       "javascript",
			rule:      "javascript%2Fsqlinjection",
			cwes:      "CWE-89,CWE-ZZ",
			cves:      "CVE-2020-1234",
			issueType: types.DependencyVulnerability,
			expCWEs:   []string{"CWE-89", "CWE-ZZ"},
			expCVEs:   []string{"CVE-2020-1234"},
		},
		{
			// Confirms the JSON-number round-trip lands on int8(5) for SecretsIssue.
			name:      "SecretsIssue",
			eco:       "",
			rule:      "",
			cwes:      "CWE-798",
			cves:      "",
			issueType: types.SecretsIssue,
			expCWEs:   []string{"CWE-798"},
			expCVEs:   []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			data := types.CommandData{
				Title:     types.GetLearnLesson,
				CommandId: types.GetLearnLesson,
				Arguments: []any{tt.rule, tt.eco, tt.cwes, tt.cves, float64(tt.issueType)},
			}
			mockService := mock_learn.NewMockService(ctrl)
			cut := getLearnLesson{learnService: mockService, command: data}
			expectedLessonURL := "https://lessonURL"
			expectedLesson := &learn.Lesson{Url: expectedLessonURL}
			mockService.EXPECT().
				GetLesson(tt.eco, tt.rule, tt.expCWEs, tt.expCVEs, tt.issueType).
				Return(expectedLesson, nil)

			lesson, err := cut.Execute(t.Context())

			assert.NoError(t, err)
			assert.Equal(t, expectedLesson, lesson)
		})
	}
}
