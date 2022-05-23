package instrumentation

import (
	"context"

	"github.com/getsentry/sentry-go"

	"github.com/snyk/snyk-ls/config"
)

type Span interface {
	StartSpan(ctx context.Context, operation string, transactionName string)
	Finish()
	Context() context.Context
}

type noopImpl struct {
	ctx context.Context
}

type sentrySpan struct {
	span *sentry.Span
}

func (s *sentrySpan) StartSpan(ctx context.Context, operation string, transactionName string) {
	var options []sentry.SpanOption
	if transactionName != "" {
		options = append(options, sentry.TransactionName(transactionName))
	}
	s.span = sentry.StartSpan(ctx, operation, options...)
	s.span.SetTag("version", config.Version)
	s.span.SetTag("organization", config.CurrentConfig().GetOrganization())
}

func (s *sentrySpan) Finish() {
	s.span.Finish()
}

func (s *sentrySpan) Context() context.Context {
	return s.span.Context()
}

func New() Span {
	if config.CurrentConfig().IsTelemetryEnabled() {
		return &sentrySpan{}
	}
	return &noopImpl{}
}

func (n *noopImpl) StartSpan(ctx context.Context, _ string, _ string) {
	n.ctx = ctx
}
func (n *noopImpl) Finish()                  {}
func (n *noopImpl) Context() context.Context { return n.ctx }
