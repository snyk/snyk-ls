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

package oss

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestScanner_GetInlineValues_shouldCallPackageScanForHTMLFiles(t *testing.T) {
	testutil.IntegTest(t)

	path, err := filepath.Abs(filepath.Join("testdata", "test.html"))
	assert.NoError(t, err)
	outputFile := filepath.Join("testdata", "packageScanTestHtmlOutput.json")

	instrumentor := performance.NewLocalInstrumentor()
	errorReporter := error_reporting.NewTestErrorReporter()
	analytics := ux.NewTestAnalytics()
	notifier := notification.NewNotifier()
	executor := cli.NewTestExecutorWithResponseFromFile(outputFile)
	scanner := NewCliScanner(
		instrumentor,
		errorReporter,
		analytics,
		executor,
		getLearnMock(t), notifier,
	).(snyk.InlineValueProvider)

	values, err := scanner.GetInlineValues(
		path,
		snyk.Range{Start: snyk.Position{Line: 0, Character: 0}, End: snyk.Position{Line: 10, Character: 150}},
	)

	assert.NoError(t, err)
	assert.Len(t, values, 2)
}
