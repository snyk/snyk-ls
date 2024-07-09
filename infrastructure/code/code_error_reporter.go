/*
 * © 2024 Snyk Limited All rights reserved.
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

package code

import (
	codeClient "github.com/snyk/code-client-go/observability"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
)

// A Sentry implementation of our error reporter that respects user preferences regarding tracking
// And can be used for Snyk Code scanning
type codeErrorReporter struct {
	errorReporter error_reporting.ErrorReporter
}

func (c codeErrorReporter) FlushErrorReporting() {
	c.errorReporter.FlushErrorReporting()
}

func (c *codeErrorReporter) CaptureError(err error, options codeClient.ErrorReporterOptions) bool {
	if options.ErrorDiagnosticPath != "" {
		return c.errorReporter.CaptureErrorAndReportAsIssue(options.ErrorDiagnosticPath, err)
	} else {
		return c.errorReporter.CaptureError(err)
	}
}

func NewCodeErrorReporter(errorReporter error_reporting.ErrorReporter) codeClient.ErrorReporter {
	return &codeErrorReporter{
		errorReporter: errorReporter,
	}
}

type testCodeErrorReporter struct{}

func newTestCodeErrorReporter() codeClient.ErrorReporter {
	return &testCodeErrorReporter{}
}

func (s *testCodeErrorReporter) FlushErrorReporting() {
}

func (s *testCodeErrorReporter) CaptureError(err error, options codeClient.ErrorReporterOptions) bool {
	return true
}
