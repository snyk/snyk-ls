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
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
)

// A Sentry implementation of our error reporter that respects user preferences regarding tracking
type gdprAwareSentryErrorReporter struct {
	notifier notification.Notifier
}

func (s *gdprAwareSentryErrorReporter) CaptureErrorAndReportAsIssue(path string, err error) bool {
	if s.notifier != nil {
		s.notifier.SendErrorDiagnostic(path, err)
	}
	return s.sendToSentry(err)
}

func NewSentryErrorReporter(notifier notification.Notifier) error_reporting.ErrorReporter {
	initializeSentry()
	return &gdprAwareSentryErrorReporter{notifier: notifier}
}

func (s *gdprAwareSentryErrorReporter) FlushErrorReporting() {
	// Set the timeout to the maximum duration the program can afford to wait
	defer sentry.Flush(2 * time.Second)
}

func (s *gdprAwareSentryErrorReporter) CaptureError(err error) bool {
	s.notifier.SendError(err)
	return s.sendToSentry(err)
}

func (s *gdprAwareSentryErrorReporter) sendToSentry(err error) (reportedToSentry bool) {
	if config.CurrentConfig().IsErrorReportingEnabled() {
		eventId := sentry.CaptureException(err)
		if eventId != nil {
			log.Info().Err(err).Str("method", "CaptureError").Msgf("Sent error to Sentry (ID: %v)", *eventId)
			return true
		}
	}
	return false
}
