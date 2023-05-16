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
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
)

func Test_getLearnLesson_Execute(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	eco := "javascript"
	rule := "javascript%2Fsqlinjection"
	cwes := "CWE-89,CWE-ZZ"
	cves := "CVE-2020-1234"
	data := snyk.CommandData{
		Title:     snyk.GetLearnLesson,
		CommandId: snyk.GetLearnLesson,
		Arguments: []any{rule, eco, cwes, cves, snyk.DependencyVulnerability},
	}
	mockService := mock_learn.NewMockService(ctrl)
	cut := getLearnLesson{learnService: mockService, command: data}
	expectedLessonURL := "https://lessonURL"
	expectedLesson := learn.Lesson{Url: expectedLessonURL}
	mockService.EXPECT().
		GetLesson(eco, rule, []string{"CWE-89", "CWE-ZZ"}, []string{"CVE-2020-1234"}, snyk.DependencyVulnerability).
		Return(expectedLesson, nil)

	lesson, err := cut.Execute(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, expectedLesson, lesson)
}
