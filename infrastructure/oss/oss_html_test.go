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

// htmlStubIssueProvider resolves MatchingIssueKeys for OSS HTML tests.
type htmlStubIssueProvider struct {
	byKey map[string]types.Issue
}

func (h htmlStubIssueProvider) Issue(key string) types.Issue {
	if h.byKey == nil {
		return nil
	}
	return h.byKey[key]
}

func (htmlStubIssueProvider) IssuesForFile(types.FilePath) []types.Issue { return nil }

func (htmlStubIssueProvider) IssuesForRange(types.FilePath, types.Range) []types.Issue { return nil }

func (htmlStubIssueProvider) Issues() snyk.IssuesByFile { return nil }

func Test_OssDetailsPanel_html_noLearn(t *testing.T) {
	engine := testutil.UnitTest(t)
	expectedVariables := []string{"${headerEnd}", "${cspSource}", "${ideStyle}", "${nonce}"}
	slices.Sort(expectedVariables)

	issueAdditionalData := snyk.OssIssueData{
		Key:         "k0",
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
	}

	issue2 := snyk.OssIssueData{
		Key:         "k2",
		Title:       "myTitle2",
		Name:        "myIssue2",
		Description: "- list2",
		From:        []string{"5", "6", "7", "8"},
	}

	issueAdditionalData.MatchingIssueKeys = []string{"k0", "k2"}

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	stub := htmlStubIssueProvider{byKey: map[string]types.Issue{
		"k0": &snyk.Issue{AdditionalData: issueAdditionalData},
		"k2": &snyk.Issue{AdditionalData: issue2},
	}}

	// invoke methode under test
	htmlRenderer, err := NewHtmlRenderer(engine)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue, stub)

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
	assert.False(t, strings.Contains(issueDetailsPanelHtml, "Learn about this issue type"))
}

func Test_OssDetailsPanel_html_withLearn(t *testing.T) {
	engine := testutil.UnitTest(t)

	issueAdditionalData := snyk.OssIssueData{
		Key:         "k0",
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		Lesson:      "something",
	}
	issueAdditionalData.MatchingIssueKeys = []string{"k0"}

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	stub := htmlStubIssueProvider{byKey: map[string]types.Issue{"k0": issue}}

	// invoke methode under test
	htmlRenderer, err := NewHtmlRenderer(engine)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue, stub)

	assert.True(t, strings.Contains(issueDetailsPanelHtml, "Learn about this issue type"))
}

func Test_OssDetailsPanel_html_withLearn_withCustomEndpoint(t *testing.T) {
	engine := testutil.UnitTest(t)

	issueAdditionalData := snyk.OssIssueData{
		Key:         "k0",
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		Lesson:      "something",
	}

	issueAdditionalData.MatchingIssueKeys = []string{"k0", "k1"}
	sibling := snyk.OssIssueData{Key: "k1", From: []string{"1", "2", "3", "4"}}

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	stub := htmlStubIssueProvider{byKey: map[string]types.Issue{
		"k0": issue,
		"k1": &snyk.Issue{AdditionalData: sibling},
	}}

	htmlRenderer, err := NewHtmlRenderer(engine)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue, stub)

	assert.Truef(t, strings.Contains(issueDetailsPanelHtml, "learn."), issueDetailsPanelHtml)
}

func Test_OssDetailsPanel_html_moreDetailedPaths(t *testing.T) {
	engine := testutil.UnitTest(t)
	expectedVariables := []string{"${headerEnd}", "${cspSource}", "${ideStyle}", "${nonce}"}
	slices.Sort(expectedVariables)

	issueAdditionalData := snyk.OssIssueData{
		Key:         "k1",
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		CVSSv3:      "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P",
		CvssScore:   5.0,
		CvssSources: []types.CvssSource{
			{
				Type:        "primary",
				CvssVersion: "3.1",
				Vector:      "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P",
			},
		},
	}

	issue2 := snyk.OssIssueData{
		Key:         "k2",
		Title:       "myTitle2",
		Name:        "myIssue2",
		Description: "- list2",
		From:        []string{"5", "6", "7", "8"},
	}

	issue3 := snyk.OssIssueData{
		Key:         "k3",
		Title:       "myTitle3",
		Name:        "myIssue3",
		Description: "- list3",
		From:        []string{"9", "10"},
	}

	issue4 := snyk.OssIssueData{
		Key:         "k4",
		Title:       "myTitle4",
		Name:        "myIssue4",
		Description: "- list4",
		From:        []string{"11"},
	}
	issueAdditionalData.MatchingIssueKeys = []string{"k1", "k2", "k3", "k4"}

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	stub := htmlStubIssueProvider{byKey: map[string]types.Issue{
		"k1": &snyk.Issue{AdditionalData: issueAdditionalData},
		"k2": &snyk.Issue{AdditionalData: issue2},
		"k3": &snyk.Issue{AdditionalData: issue3},
		"k4": &snyk.Issue{AdditionalData: issue4},
	}}

	// invoke methode under test
	htmlRenderer, err := NewHtmlRenderer(engine)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue, stub)

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
	assert.False(t, strings.Contains(issueDetailsPanelHtml, "Learn about this issue type"))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "...and"))
	// Test that the computed CVSS calculator URL is present
	expectedUrl := types.GetCvssCalculatorUrl(issueAdditionalData.CvssSources)
	assert.True(t, strings.Contains(issueDetailsPanelHtml, expectedUrl))
}

func Test_OssDetailsPanel_html_withAnnotationsPolicy(t *testing.T) {
	engine := testutil.UnitTest(t)

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
	htmlRenderer, err := NewHtmlRenderer(engine)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue, nil)

	// Assert
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "User note"))
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "Note reason"))
}

func Test_OssDetailsPanel_html_withSeverityChangePolicy(t *testing.T) {
	engine := testutil.UnitTest(t)

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
	htmlRenderer, err := NewHtmlRenderer(engine)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue, nil)

	// Assert
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "A policy has affected the severity of this issue. It was originally critical severity"))
}
func Test_OssDetailsPanel_html_hasCSS(t *testing.T) {
	engine := testutil.UnitTest(t)

	issueAdditionalData := snyk.OssIssueData{
		Title:       "myTitle",
		Name:        "myIssue",
		Description: "- list",
		From:        []string{"1", "2", "3", "4"},
		CVSSv3:      "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P",
	}

	issue := &snyk.Issue{
		ID:             "randomId",
		Severity:       types.Critical,
		AdditionalData: issueAdditionalData,
	}

	// invoke methode under test
	htmlRenderer, err := NewHtmlRenderer(engine)
	assert.NoError(t, err)
	issueDetailsPanelHtml := htmlRenderer.GetDetailsHtml(issue, nil)

	// check if styles are present
	assert.True(t, strings.Contains(issueDetailsPanelHtml, "--default-font: \"SF Pro Text\", \"Segoe UI\", \"Ubuntu\", Geneva, Verdana, Tahoma, sans-serif;\n"))
}
