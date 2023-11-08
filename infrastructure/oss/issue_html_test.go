/*
 * © 2022-2023 Snyk Limited
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

package oss

import (
	_ "embed"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_OssDetailsPanel_html_noLearn(t *testing.T) {
	_ = testutil.UnitTest(t)
	expectedVariables := []string{"${headerEnd}", "${cspSource}", "${nonce}", "${severityIcon}", "${learnIcon}"}
	slices.Sort(expectedVariables)

	issue := &ossIssue{
		Title:       "myTitle",
		Name:        "myIssue",
		Severity:    "SuperCritical",
		Id:          "randomId",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
	}

	issue2 := &ossIssue{
		Title:       "myTitle2",
		Name:        "myIssue2",
		Severity:    "SuperCritical",
		Id:          "randomId2",
		Description: "- list2",
		From:        []string{"5", "6", "7", "8"},
	}

	issue.matchingIssues = append(issue.matchingIssues, issue)
	issue.matchingIssues = append(issue.matchingIssues, issue2)

	// invoke methode under test
	issueDetailsPanelHtml := getDetailsHtml(issue)

	// compare
	reg := regexp.MustCompile("\\$\\{\\w+\\}")
	actualVariables := reg.FindAllString(issueDetailsPanelHtml, -1)
	slices.Sort(actualVariables)
	actualVariables = slices.Compact(actualVariables)

	assert.Equal(t, expectedVariables, actualVariables)

	assert.True(t, strings.Contains(issueDetailsPanelHtml, issue.Name))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, issue.Id))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, issue.Title))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, issue.Severity))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, strings.Join(issue.From, " > ")))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, strings.Join(issue2.From, " > ")))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "<li>list</li>"))
	assert.False(t, strings.Contains(issueDetailsPanelHtml, "Learn about this vulnerability"))
}

func Test_OssDetailsPanel_html_withLearn(t *testing.T) {
	_ = testutil.UnitTest(t)

	lesson := &learn.Lesson{Url: "something"}

	issue := &ossIssue{
		Title:       "myTitle",
		Name:        "myIssue",
		Severity:    "SuperCritical",
		Id:          "randomId",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		lesson:      lesson,
	}

	issue.matchingIssues = append(issue.matchingIssues, issue)

	// invoke methode under test
	issueDetailsPanelHtml := getDetailsHtml(issue)

	assert.True(t, strings.Contains(issueDetailsPanelHtml, "Learn about this vulnerability"))
}
