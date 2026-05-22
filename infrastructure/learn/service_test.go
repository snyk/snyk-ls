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

package learn

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_GetLearnEndpoint(t *testing.T) {
	engine := testutil.UnitTest(t)
	config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.snyk.io")
	engineConfig := engine.GetConfiguration()
	logger := engine.GetLogger()
	cut := New(engineConfig, logger, engine.GetNetworkAccess().GetUnauthorizedHttpClient)

	endpoint, err := cut.LearnEndpoint()

	assert.NoError(t, err)
	assert.Equal(t, "https://api.snyk.io/v1/learn", endpoint)
}

func getRealOSSLookupParams() *LessonLookupParams {
	params := &LessonLookupParams{
		CWEs:      []string{"CWE-601"},
		Rule:      "SNYK-JS-ASYNC-2441827",
		Ecosystem: "npm",
	}
	return params
}

func getRealCodeLookupParams() LessonLookupParams {
	params := LessonLookupParams{
		Rule:      "javascript/sqlinjection",
		Ecosystem: "javascript",
		CWEs:      []string{"CWE-89"},
	}
	return params
}

func Test_GetLesson(t *testing.T) {
	engine := testutil.SmokeTest(t, "", "SMOKE_SHARD_4")
	config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.snyk.io")
	engineConfig := engine.GetConfiguration()
	logger := engine.GetLogger()
	cut := New(engineConfig, logger, engine.GetNetworkAccess().GetUnauthorizedHttpClient)
	_, err := cut.GetAllLessons()
	assert.NoError(t, err)
	t.Run("OSS issue - lesson returned", func(t *testing.T) {
		params := getRealOSSLookupParams()

		lesson, err := cut.GetLesson(params.Ecosystem, params.Rule, params.CWEs, params.CVEs, types.DependencyVulnerability)

		assert.NoError(t, err)
		assert.NotEmpty(t, lesson)
		assert.True(t, strings.HasSuffix(lesson.Url, "?loc=ide"), "should have ?loc=ide suffix")
	})

	t.Run("OSS license - no lessons returned", func(t *testing.T) {
		testutil.SmokeTest(t, "", "SMOKE_SHARD_4")
		params := getRealOSSLookupParams()

		lesson, err := cut.GetLesson(params.Ecosystem, params.Rule, params.CWEs, params.CVEs, types.LicenseIssue)

		assert.NoError(t, err)
		assert.Empty(t, lesson)
	})
	t.Run("Code security - lesson returned - javascript", func(t *testing.T) {
		params := getRealCodeLookupParams()

		checkLesson(t, cut, params)
	})

	t.Run("Code security - lesson returned - java", func(t *testing.T) {
		params := getRealCodeLookupParams()
		params.Ecosystem = "java"

		checkLesson(t, cut, params)
	})

	t.Run("Snyk Secrets - lesson returned", func(t *testing.T) {
		// Secrets findings produce empty Ecosystem and empty Rule (see infrastructure/secrets/convert.go);
		// the cache-fall-through to all-lessons + filterForCWEs is what resolves the lesson.
		lesson, err := cut.GetLesson("", "", []string{"CWE-798"}, nil, types.SecretsIssue)

		assert.NoError(t, err)
		assert.NotEmpty(t, lesson)
		assert.True(t, strings.HasSuffix(lesson.Url, "?loc=ide"), "should have ?loc=ide suffix")
		assert.Contains(t, lesson.Cwes, "CWE-798")
	})
}

// Test_lessonsLookupParams is a white-box unit test for the unexported lessonsLookupParams.
// It runs without network access and exercises every supported IssueType so additions for
// new products do not silently regress the existing OSS/Code mappings.
func Test_lessonsLookupParams(t *testing.T) {
	testutil.UnitTest(t)
	s := &serviceImpl{}

	tests := []struct {
		name      string
		ecosystem string
		rule      string
		cwes      []string
		cves      []string
		issueType types.IssueType
		want      *LessonLookupParams
	}{
		{
			name:      "DependencyVulnerability passes through rule and ecosystem",
			ecosystem: "npm",
			rule:      "SNYK-JS-ASYNC-2441827",
			cwes:      []string{"CWE-601"},
			cves:      []string{"CVE-2021-43138"},
			issueType: types.DependencyVulnerability,
			want: &LessonLookupParams{
				Rule:      "SNYK-JS-ASYNC-2441827",
				Ecosystem: "npm",
				CWEs:      []string{"CWE-601"},
				CVEs:      []string{"CVE-2021-43138"},
			},
		},
		{
			name:      "CodeSecurityVulnerability splits language/ruleId on '/'",
			ecosystem: "ignored-by-code-path",
			rule:      "javascript/sqlinjection",
			cwes:      []string{"CWE-89"},
			cves:      nil,
			issueType: types.CodeSecurityVulnerability,
			want: &LessonLookupParams{
				Rule:      "sqlinjection",
				Ecosystem: "javascript",
				CWEs:      []string{"CWE-89"},
				CVEs:      []string{},
			},
		},
		{
			name:      "SecretsIssue with empty ecosystem and rule (realistic input from secrets path)",
			ecosystem: "",
			rule:      "",
			cwes:      []string{"CWE-798"},
			cves:      nil,
			issueType: types.SecretsIssue,
			want: &LessonLookupParams{
				Rule:      "",
				Ecosystem: "",
				CWEs:      []string{"CWE-798"},
				CVEs:      []string{},
			},
		},
		{
			name:      "SecretsIssue keeps CVEs when present",
			ecosystem: "",
			rule:      "",
			cwes:      []string{"CWE-798"},
			cves:      []string{"CVE-2024-12345"},
			issueType: types.SecretsIssue,
			want: &LessonLookupParams{
				Rule:      "",
				Ecosystem: "",
				CWEs:      []string{"CWE-798"},
				CVEs:      []string{"CVE-2024-12345"},
			},
		},
		{
			name:      "SecretsIssue takes only the first CWE when multiple are passed",
			ecosystem: "",
			rule:      "",
			cwes:      []string{"CWE-798", "CWE-259"},
			cves:      nil,
			issueType: types.SecretsIssue,
			want: &LessonLookupParams{
				Rule:      "",
				Ecosystem: "",
				CWEs:      []string{"CWE-798"},
				CVEs:      []string{},
			},
		},
		{
			name:      "Unsupported IssueType returns nil (default branch)",
			ecosystem: "npm",
			rule:      "rule-id",
			cwes:      []string{"CWE-1"},
			cves:      nil,
			issueType: types.LicenseIssue,
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.lessonsLookupParams(tt.ecosystem, tt.rule, tt.cwes, tt.cves, tt.issueType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func checkLesson(t *testing.T, cut Service, params LessonLookupParams) {
	t.Helper()
	lesson, err := cut.GetLesson(params.Ecosystem, params.Rule, params.CWEs, params.CVEs, types.CodeSecurityVulnerability)

	assert.NoError(t, err)
	assert.NotEmpty(t, lesson)
	assert.Contains(t, lesson.Cwes, params.CWEs[0])
	assert.Contains(t, lesson.Ecosystems, params.Ecosystem)
}
