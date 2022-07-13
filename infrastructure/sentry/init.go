package sentry

import (
	"github.com/denisbrodbeck/machineid"
	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/concurrency"
)

const sentryDsn = "https://f760a2feb30c40198cef550edf6221de@o30291.ingest.sentry.io/6242547"

var initialized = concurrency.AtomicBool{}

func initializeSentry() {
	if initialized.Get() {
		return
	}
	initialized.Set(true)
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              sentryDsn,
		Environment:      sentryEnvironment(),
		Release:          config.Version,
		Debug:            config.IsDevelopment(),
		BeforeSend:       beforeSend,
		TracesSampleRate: 1,
	})
	if err != nil {
		log.Error().Str("method", "Initialize").Msg(err.Error())
	} else {
		log.Info().Msg("Error reporting initialized")
	}
	addUserId()
}

func addUserId() {
	id, machineErr := machineid.ProtectedID("Snyk-LS")
	if machineErr != nil && config.CurrentConfig().IsErrorReportingEnabled() {
		log.Err(machineErr).Str("method", "initializeSentry").Msg("cannot retrieve machine id")
		sentry.CaptureException(machineErr)
	} else {
		sentry.ConfigureScope(func(scope *sentry.Scope) {
			scope.SetUser(sentry.User{ID: id})
		})
	}
}

func beforeSend(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
	if config.CurrentConfig().IsErrorReportingEnabled() {
		return event
	}
	return nil
}

func sentryEnvironment() string {
	if config.IsDevelopment() {
		return "development"
	} else {
		return "production"
	}
}
