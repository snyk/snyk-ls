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

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_OssDetailsPanel_html_noLearn(t *testing.T) {
	_ = testutil.UnitTest(t)
	expectedVariables := []string{"${headerEnd}", "${cspSource}", "${ideStyle}", "${nonce}"}
	slices.Sort(expectedVariables)

	issueAdditionalData := snyk.OssIssueData{
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
	}

	issue2 := snyk.OssIssueData{
		Title:       "myTitle2",
		Name:        "myIssue2",
		Description: "- list2",
		From:        []string{"5", "6", "7", "8"},
	}

	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issueAdditionalData)
	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issue2)

	issue := snyk.Issue{
		ID:             "randomId",
		Severity:       snyk.Critical,
		AdditionalData: issueAdditionalData,
	}

	// invoke methode under test
	issueDetailsPanelHtml := getDetailsHtml(issue)

	// compare
	reg := regexp.MustCompile(`\$\{\w+\}`)
	actualVariables := reg.FindAllString(issueDetailsPanelHtml, -1)
	slices.Sort(actualVariables)
	actualVariables = slices.Compact(actualVariables)

	assert.Equal(t, expectedVariables, actualVariables)

	assert.True(t, strings.Contains(issueDetailsPanelHtml, issueAdditionalData.Name))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, issue.ID))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, issueAdditionalData.Title))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, issue.Severity.String()))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, strings.Join(issueAdditionalData.From, " &gt; ")))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, strings.Join(issue2.From, " &gt; ")))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "<li>list</li>"))
	assert.False(t, strings.Contains(issueDetailsPanelHtml, "Learn about this vulnerability"))
}

func Test_OssDetailsPanel_html_withLearn(t *testing.T) {
	_ = testutil.UnitTest(t)

	issueAdditionalData := snyk.OssIssueData{
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		Lesson:      "something",
	}

	issue := snyk.Issue{
		ID:             "randomId",
		Severity:       snyk.Critical,
		AdditionalData: issueAdditionalData,
	}

	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issueAdditionalData)

	// invoke methode under test
	issueDetailsPanelHtml := getDetailsHtml(issue)

	assert.True(t, strings.Contains(issueDetailsPanelHtml, "Learn about this vulnerability"))
}

func Test_OssDetailsPanel_html_withLearn_withCustomEndpoint(t *testing.T) {
	c := testutil.UnitTest(t)

	customEndpoint := "https://app.dev.snyk.io"
	c.UpdateApiEndpoints(customEndpoint + "/api")

	issueAdditionalData := snyk.OssIssueData{
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		Lesson:      "something",
		MatchingIssues: []snyk.OssIssueData{
			{
				From: []string{"1", "2", "3", "4"},
			},
		},
	}

	issue := snyk.Issue{
		ID:             "randomId",
		Severity:       snyk.Critical,
		AdditionalData: issueAdditionalData,
	}

	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issueAdditionalData)

	issueDetailsPanelHtml := getDetailsHtml(issue)

	assert.True(t, strings.Contains(issueDetailsPanelHtml, customEndpoint))
}
