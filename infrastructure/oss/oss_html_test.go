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
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_OssDetailsPanel_html_noLearn(t *testing.T) {
	c := testutil.UnitTest(t)
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

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	// invoke methode under test
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue)

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
	assert.False(t, strings.Contains(issueDetailsPanelHtml, "Learn about this issue"))
}

func Test_OssDetailsPanel_html_withLearn(t *testing.T) {
	c := testutil.UnitTest(t)

	issueAdditionalData := snyk.OssIssueData{
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		Lesson:      "something",
	}

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issueAdditionalData)

	// invoke methode under test
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue)

	assert.True(t, strings.Contains(issueDetailsPanelHtml, "Learn about this issue"))
}

func Test_OssDetailsPanel_html_withLearn_withCustomEndpoint(t *testing.T) {
	c := testutil.UnitTest(t)

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

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issueAdditionalData)

	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue)

	assert.Truef(t, strings.Contains(issueDetailsPanelHtml, "learn."), issueDetailsPanelHtml)
}

func Test_OssDetailsPanel_html_moreDetailedPaths(t *testing.T) {
	c := testutil.UnitTest(t)
	expectedVariables := []string{"${headerEnd}", "${cspSource}", "${ideStyle}", "${nonce}"}
	slices.Sort(expectedVariables)

	issueAdditionalData := snyk.OssIssueData{
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		CVSSv3:      "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P",
		CvssScore:   5.0,
	}

	issue2 := snyk.OssIssueData{
		Title:       "myTitle2",
		Name:        "myIssue2",
		Description: "- list2",
		From:        []string{"5", "6", "7", "8"},
	}

	issue3 := snyk.OssIssueData{
		Title:       "myTitle3",
		Name:        "myIssue3",
		Description: "- list3",
		From:        []string{"9", "10"},
	}

	issue4 := snyk.OssIssueData{
		Title:       "myTitle4",
		Name:        "myIssue4",
		Description: "- list4",
		From:        []string{"11"},
	}
	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issueAdditionalData)
	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issue2)
	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issue3)
	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issue4)

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	// invoke methode under test
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue)

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
	assert.False(t, strings.Contains(issueDetailsPanelHtml, "Learn about this issue"))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "...and"))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P"))
}

func Test_OssDetailsPanel_html_withAnnotationsPolicy(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	issueAdditionalData := snyk.OssIssueData{
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		AppliedPolicyRules: snyk.AppliedPolicyRules{
			Annotation: snyk.Annotation{
				Value:  "This vulnerability was overridden to low severity due to our internal risk assessment that determined it poses minimal risk in our environment.",
				Reason: "Our application does not use the affected functionality in a way that exposes it to the vulnerability. Therefore, it has a lower priority for fixing compared to other issues.",
			},
		},
	}

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Low,
		AdditionalData: issueAdditionalData,
	}

	// Act
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue)

	// Assert
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "User note"))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "Note reason"))
}

func Test_OssDetailsPanel_html_withSeverityChangePolicy(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	issueAdditionalData := snyk.OssIssueData{
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		AppliedPolicyRules: snyk.AppliedPolicyRules{
			SeverityChange: snyk.SeverityChange{
				OriginalSeverity: types.Critical.String(),
				NewSeverity:      types.Low.String(),
				Reason:           "Changing severity to low due to internal risk assessment.",
			},
		},
	}

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Low,
		AdditionalData: issueAdditionalData,
	}

	// Act
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue)

	// Assert
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "A policy has affected the severity of this issue. It was originally critical severity"))
}
func Test_OssDetailsPanel_html_hasCSS(t *testing.T) {
	c := testutil.UnitTest(t)

	issueAdditionalData := snyk.OssIssueData{
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		CVSSv3:      "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P",
	}

	issueAdditionalData.MatchingIssues = append(issueAdditionalData.MatchingIssues, issueAdditionalData)

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	// invoke methode under test
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue)

	// check if styles are present
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "--default-font: \"SF Pro Text\", \"Segoe UI\", \"Ubuntu\", Geneva, Verdana, Tahoma, sans-serif;\n"))
}
