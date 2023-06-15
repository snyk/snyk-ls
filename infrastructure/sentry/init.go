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
		EnableTracing:    true,
		TracesSampleRate: 1,
		HTTPClient:       config.CurrentConfig().Engine().GetNetworkAccess().GetUnauthorizedHttpClient(),
		AttachStacktrace: true,
	})
	if err != nil {
		log.Error().Str("method", "Initialize").Msg(err.Error())
	} else {
		log.Info().Msg("Error reporting initialized")
	}
	addUserId()
}

func addUserId() {
	device := config.CurrentConfig().DeviceID()
	if device != "" {
		sentry.ConfigureScope(func(scope *sentry.Scope) {
			scope.SetUser(sentry.User{ID: device})
		})
	}
}

func beforeSend(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
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
