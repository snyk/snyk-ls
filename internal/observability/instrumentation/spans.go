package instrumentation

import (
	"context"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
)

type noopSpan struct {
	operation string
	txName    string
	started   bool
	finished  bool
}

type sentrySpan struct {
	span      *sentry.Span
	txName    string
	operation string
}

func (s *sentrySpan) GetTxName() string {
	return s.txName
}

func (s *sentrySpan) GetOperation() string {
	return s.operation
}

func (s *sentrySpan) StartSpan(ctx context.Context) {
	var options []sentry.SpanOption
	if s.txName != "" {
		options = append(options, sentry.TransactionName(s.txName))
	}
	s.span = sentry.StartSpan(ctx, s.operation, options...)
	s.span.SetTag("organization", config.CurrentConfig().GetOrganization())
	log.Debug().
		Str("method", "sentrySpan.StartSpan").
		Str("operation", s.operation).
		Str("txName", s.txName).
		Msg("starting span")
}

func (s *sentrySpan) Finish() {
	log.Debug().
		Str("method", "sentrySpan.Finish").
		Str("operation", s.span.Op).
		Msg("finishing span")
	s.span.Finish()
}

func (s *sentrySpan) SetTransactionName(name string) {
	if s.txName != "" {
		s.txName = name
	}
}

func (n *noopSpan) Finish() {
	n.started = false
	n.finished = true
	log.Debug().
		Str("method", "noopSpan.Finish").
		Str("operation", n.operation).
		Msg("finishing span")
}

func (n *noopSpan) SetTransactionName(txName string) { n.txName = txName }
func (n *noopSpan) StartSpan(_ context.Context) {
	log.Debug().
		Str("method", "noopSpan.StartSpan").
		Str("operation", n.operation).
		Msg("starting span")
	n.started = true
}

func (n *noopSpan) GetOperation() string {
	return n.operation
}
func (n *noopSpan) GetTxName() string {
	return n.txName
}
