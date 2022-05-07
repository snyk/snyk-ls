package error_reporting

import (
	"context"
	"fmt"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/notification"

	"github.com/getsentry/sentry-go"
)

const sentryDsn = "https://f760a2feb30c40198cef550edf6221de@o30291.ingest.sentry.io/6242547"

var logger = environment.Logger

func InitErrorReporting() {
	err := sentry.Init(sentry.ClientOptions{
		Dsn:         sentryDsn,
		Environment: determineEnvironment(),
		Release:     config.Version,
		Debug:       config.IsDevelopment,
		BeforeSend:  beforeSend,
	})
	if err != nil {
		logger.
			WithField("method", "InitErrorReporting").
			WithError(err).
			Error(context.Background(), "couldn't initialize Sentry")
	} else {
		logger.
			WithField("method", "InitErrorReporting").
			Info(context.Background(), "Sentry initialized")
	}
}

func FlushErrorReporting() {
	// Set the timeout to the maximum duration the program can afford to wait
	defer sentry.Flush(2 * time.Second)
}

func CaptureError(err error) bool {
	if config.IsErrorReportingEnabled {
		sentry.CaptureException(err)
		notification.Send(sglsp.ShowMessageParams{
			Type:    sglsp.MTError,
			Message: fmt.Sprintf("Snyk encountered an error while scanning: %v", err),
		})
		return true
	}
	return false
}

func beforeSend(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
	if config.IsErrorReportingEnabled {
		return event
	}
	return nil
}

func determineEnvironment() string {
	if config.IsDevelopment {
		return "development"
	} else {
		return "production"
	}
}
