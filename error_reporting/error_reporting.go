package error_reporting

import (
	"time"

	"github.com/snyk/snyk-ls/config"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"
)

const sentryDsn = "https://f760a2feb30c40198cef550edf6221de@o30291.ingest.sentry.io/6242547"

func InitErrorReporting() {
	err := sentry.Init(sentry.ClientOptions{
		Dsn:         sentryDsn,
		Environment: environment(),
		Release:     config.Version,
		Debug:       config.IsDevelopment,
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
	if config.IsErrorReportingEnabled {
		sentry.CaptureException(err)
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

func environment() string {
	if config.IsDevelopment {
		return "development"
	} else {
		return "production"
	}
}
