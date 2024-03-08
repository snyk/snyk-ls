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
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"
	codeClient "github.com/snyk/code-client-go/observability"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/notification"
)

// A Sentry implementation of our error reporter that respects user preferences regarding tracking
// And can be used for Snyk Code scanning
type codeErrorReporter struct {
	notifier notification.Notifier
}

func (c codeErrorReporter) FlushErrorReporting() {
	// Set the timeout to the maximum duration the program can afford to wait
	defer sentry.Flush(2 * time.Second)
}

func (c *codeErrorReporter) CaptureError(err error, options codeClient.ErrorReporterOptions) bool {
	if options.ErrorDiagnosticPath != "" && c.notifier != nil {
		c.notifier.SendErrorDiagnostic(options.ErrorDiagnosticPath, err)
	} else {
		c.notifier.SendError(err)
	}
	return c.sendToSentry(err)
}

func (s *codeErrorReporter) sendToSentry(err error) (reportedToSentry bool) {
	if config.CurrentConfig().IsErrorReportingEnabled() {
		eventId := sentry.CaptureException(err)
		if eventId != nil {
			log.Info().Err(err).Str("method", "CaptureError").Msgf("Sent error to Sentry (ID: %v)", *eventId)
			return true
		}
	}
	return false
}

func NewCodeErrorReporter(notifier notification.Notifier) codeClient.ErrorReporter {
	return &codeErrorReporter{
		notifier: notifier,
	}
}

type testCodeErrorReporter struct{}

func newTestCodeErrorReporter() codeClient.ErrorReporter {
	return &testCodeErrorReporter{}
}

func (s *testCodeErrorReporter) FlushErrorReporting() {
}

func (s *testCodeErrorReporter) CaptureError(err error, options codeClient.ErrorReporterOptions) bool {
	log.Log().Err(err).Msg("An error has been captured by the testing error reporter")
	return true
}
