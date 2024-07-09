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
	"github.com/snyk/snyk-ls/domain/snyk"
	errorreporting "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_GetLearnEndpoint(t *testing.T) {
	testutil.UnitTest(t)
	c := config.CurrentConfig()
	c.UpdateApiEndpoints("https://snyk.io/api")
	cut := New(c, c.Engine().GetNetworkAccess().GetUnauthorizedHttpClient, errorreporting.NewTestErrorReporter())

	endpoint, err := cut.LearnEndpoint(c)

	assert.NoError(t, err)
	assert.Equal(t, "https://api.snyk.io/v1/learn", endpoint)
}

func getRealOSSLookupParams() *LessonLookupParams {
	params := &LessonLookupParams{
		CWEs:      []string{"CWE-1321"},
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
	c := testutil.SmokeTest(t, false)
	c.UpdateApiEndpoints("https://snyk.io/api")
	cut := New(c, c.Engine().GetNetworkAccess().GetUnauthorizedHttpClient, errorreporting.NewTestErrorReporter())
	t.Run("OSS vulnerability - lesson returned", func(t *testing.T) {
		params := getRealOSSLookupParams()

		lesson, err := cut.GetLesson(params.Ecosystem, params.Rule, params.CWEs, params.CVEs, snyk.DependencyVulnerability)

		assert.NoError(t, err)
		assert.NotEmpty(t, lesson)
		assert.True(t, strings.HasSuffix(lesson.Url, "?loc=ide"), "should have ?loc=ide suffix")
	})

	t.Run("OSS license - no lessons returned", func(t *testing.T) {
		testutil.SmokeTest(t, false)
		params := getRealOSSLookupParams()

		lesson, err := cut.GetLesson(params.Ecosystem, params.Rule, params.CWEs, params.CVEs, snyk.LicenceIssue)

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

	t.Run("Code quality - no lessons returned", func(t *testing.T) {
		params := getRealCodeLookupParams()

		lesson, err := cut.GetLesson(params.Ecosystem, params.Rule, params.CWEs, params.CVEs, snyk.CodeQualityIssue)

		assert.NoError(t, err)
		assert.Empty(t, lesson)
	})
}

func checkLesson(t *testing.T, cut Service, params LessonLookupParams) {
	t.Helper()
	lesson, err := cut.GetLesson(params.Ecosystem, params.Rule, params.CWEs, params.CVEs, snyk.CodeSecurityVulnerability)

	assert.NoError(t, err)
	assert.NotEmpty(t, lesson)
	assert.Contains(t, lesson.Cwes, params.CWEs[0])
	assert.Contains(t, lesson.Ecosystems, params.Ecosystem)
}
