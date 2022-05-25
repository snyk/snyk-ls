package instrumentation

import (
	"context"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
)

type Span interface {
	Finish()
	Context() context.Context
	SetTransactionName(name string)
	startSpan()
}

type noopImpl struct {
	ctx       context.Context
	started   bool
	finished  bool
	hasTXName bool
}

type sentrySpan struct {
	span            *sentry.Span
	ctx             context.Context
	transactionName string
	operation       string
}

func (s *sentrySpan) startSpan() {
	var options []sentry.SpanOption
	if s.transactionName != "" {
		options = append(options, sentry.TransactionName(s.transactionName))
	}
	s.span = sentry.StartSpan(s.ctx, s.operation, options...)
	s.span.SetTag("organization", config.CurrentConfig().GetOrganization())
	log.Debug().
		Str("method", "instrumentation.StartSpan").
		Str("operation", s.operation).
		Str("transactionName", s.transactionName).
		Msg("starting span")
}

func (s *sentrySpan) SetTransactionName(name string) {
	s.transactionName = name
}

func (s *sentrySpan) Finish() {
	log.Debug().
		Str("method", "instrumentation.Finish").
		Str("operation", s.span.Op).
		Str("transactionName", s.transactionName).
		Msg("finishing span")
	s.span.Finish()
}

func (s *sentrySpan) Context() context.Context {
	return s.span.Context()
}

func StartSpan(ctx context.Context, operation string) Span {
	s := create(ctx, operation, "")
	s.startSpan()
	return s
}

func NewTransaction(ctx context.Context, txName string, operation string) Span {
	s := create(ctx, txName, operation)
	return s
}

func create(ctx context.Context, txName string, operation string) Span {
	var s Span
	if config.CurrentConfig().IsTelemetryEnabled() {
		s = &sentrySpan{ctx: ctx, operation: operation}
	} else {
		s = &noopImpl{ctx: ctx}
	}
	s.SetTransactionName(txName)
	return s
}

func (n *noopImpl) Finish() {
	n.started = false
	n.finished = true
}
func (n *noopImpl) Context() context.Context         { return n.ctx }
func (n *noopImpl) SetTransactionName(txName string) { n.hasTXName = true }
func (n *noopImpl) startSpan()                       { n.started = true }
