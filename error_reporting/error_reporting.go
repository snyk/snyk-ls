package error_reporting

import (
	"fmt"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/notification"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"
)

const sentryDsn = "https://f760a2feb30c40198cef550edf6221de@o30291.ingest.sentry.io/6242547"

func InitErrorReporting() {
	err := sentry.Init(sentry.ClientOptions{
		Dsn:         sentryDsn,
		Environment: environment(),
		Release:     config.Version,
		Debug:       config.IsDevelopment(),
		BeforeSend:  beforeSend,
	})
	if err != nil {
		log.Error().Str("method", "InitErrorReporting").Msg(err.Error())
	} else {
		log.Info().Msg("Error reporting initialized.")
	}
}

func FlushErrorReporting() {
	// Set the timeout to the maximum duration the program can afford to wait
	defer sentry.Flush(2 * time.Second)
}

func CaptureError(err error) bool {
	notification.Send(sglsp.ShowMessageParams{
		Type:    sglsp.MTError,
		Message: fmt.Sprintf("Snyk encountered an error: %v", err),
	})
	if config.CurrentConfig().IsErrorReportingEnabled() {
		log.Debug().Err(err).Str("method", "CaptureError").Msgf("Sending error to Sentry")
		sentry.CaptureException(err)
		return true
	}
	return false
}

func beforeSend(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
	if config.CurrentConfig().IsErrorReportingEnabled() {
		return event
	}
	return nil
}

func environment() string {
	if config.IsDevelopment() {
		return "development"
	} else {
		return "production"
	}
}
