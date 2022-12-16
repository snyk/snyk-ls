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

package sentry

import (
	"errors"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

var target = NewSentryErrorReporter()

func TestErrorReporting_CaptureError(t *testing.T) {
	testutil.UnitTest(t)
	e := errors.New("test error")

	notification.CreateListener(func(params interface{}) {
		showMessageParams := params.(sglsp.ShowMessageParams)
		assert.Equal(t, "Snyk encountered an error: test error", showMessageParams.Message)
	})

	config.CurrentConfig().SetErrorReportingEnabled(false)
	captured := target.CaptureError(e)
	assert.False(t, captured)

	config.CurrentConfig().SetErrorReportingEnabled(true)
	captured = target.CaptureError(e)
	assert.True(t, captured)
}

func TestErrorReporting_CaptureErrorAndReportAsIssue(t *testing.T) {
	testutil.UnitTest(t)

	path := "testPath"
	text := "test error"
	notification.CreateListener(func(params interface{}) {
		diagnosticsParams := params.(lsp.PublishDiagnosticsParams)
		assert.Equal(t, text, diagnosticsParams.Diagnostics[0].Message)
		assert.Equal(t, lsp.DiagnosticsSeverityWarning, diagnosticsParams.Diagnostics[0].Severity)
		assert.Equal(t, diagnosticsParams.URI, uri.PathToUri(path))
		assert.Equal(t, diagnosticsParams.Diagnostics[0].CodeDescription.Href, lsp.Uri("https://snyk.io/user-hub"))
	})

	e := errors.New(text)
	config.CurrentConfig().SetErrorReportingEnabled(false)
	captured := target.CaptureErrorAndReportAsIssue(path, e)
	assert.False(t, captured)

	config.CurrentConfig().SetErrorReportingEnabled(true)
	captured = target.CaptureErrorAndReportAsIssue(path, e)
	assert.True(t, captured)
}
