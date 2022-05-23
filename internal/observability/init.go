package observability

import (
	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
)

const sentryDsn = "https://f760a2feb30c40198cef550edf6221de@o30291.ingest.sentry.io/6242547"

func Initialize() {
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              sentryDsn,
		Environment:      Environment(),
		Release:          config.Version,
		Debug:            config.IsDevelopment(),
		BeforeSend:       BeforeSend,
		TracesSampleRate: 1,
	})
	if err != nil {
		log.Error().Str("method", "Initialize").Msg(err.Error())
	} else {
		log.Info().Msg("Error reporting initialized.")
	}
}

func BeforeSend(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
	if config.CurrentConfig().IsErrorReportingEnabled() {
		return event
	}
	return nil
}

func Environment() string {
	if config.IsDevelopment() {
		return "development"
	} else {
		return "production"
	}
}
