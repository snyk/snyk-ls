package sentry

import (
	"fmt"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/notification"
)

// A Sentry implementation of our error reporter that respects user preferences regarding tracking
type gdprAwareSentryErrorReporter struct{}

func NewSentryErrorReporter() error_reporting.ErrorReporter {
	initializeSentry()
	return &gdprAwareSentryErrorReporter{}
}

func (s *gdprAwareSentryErrorReporter) FlushErrorReporting() {
	// Set the timeout to the maximum duration the program can afford to wait
	defer sentry.Flush(2 * time.Second)
}

func (s *gdprAwareSentryErrorReporter) CaptureError(err error) bool {
	notification.Send(sglsp.ShowMessageParams{
		Type:    sglsp.MTError,
		Message: fmt.Sprintf("Snyk encountered an error: %v", err),
	})
	if config.CurrentConfig().IsErrorReportingEnabled() {
		eventId := sentry.CaptureException(err)
		log.Info().Err(err).Str("method", "CaptureError").Msgf("Sent error to Sentry (ID: %v)", eventId)
		return true
	}
	return false
}
