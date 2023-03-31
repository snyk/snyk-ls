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
	"context"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/performance"
)

type span struct {
	span      *sentry.Span
	txName    string
	operation string
	ctx       context.Context
}

func (s *span) GetTxName() string {
	return s.txName
}

func (s *span) GetOperation() string {
	return s.operation
}

func (s *span) GetTraceId() string {
	return s.ctx.Value(performance.TraceIdContextKey("trace_id")).(string)
}

func (s *span) Context() context.Context {
	return s.ctx
}

func (s *span) StartSpan(ctx context.Context) {
	var options []sentry.SpanOption
	if s.txName != "" {
		options = append(options, sentry.TransactionName(s.txName))
	}
	s.span = sentry.StartSpan(ctx, s.operation, options...)
	s.span.SetTag("organization", config.CurrentConfig().Organization())
	s.ctx = performance.GetContextWithTraceId(s.span.Context(), s.span.TraceID.String())

	log.Trace().
		Str("method", "sentrySpan.StartSpan").
		Str("operation", s.operation).
		Str("txName", s.txName).
		Msg("starting span")
}

func (s *span) Finish() {
	log.Trace().
		Str("method", "span.Finish").
		Str("operation", s.span.Op).
		Msg("finishing span")
	s.span.Finish()
}

func (s *span) SetTransactionName(name string) {
	if name != "" && s.txName == "" {
		s.txName = name
	}
}
