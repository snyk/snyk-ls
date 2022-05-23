package instrumentation

import (
	"context"

	"github.com/getsentry/sentry-go"

	"github.com/snyk/snyk-ls/config"
)

type Span interface {
	StartSpan(ctx context.Context, name string)
	Finish()
	Context() context.Context
}

type noopImpl struct {
	ctx context.Context
}

type sentrySpan struct {
	span *sentry.Span
}

func (s *sentrySpan) StartSpan(ctx context.Context, operation string) {
	s.span = sentry.StartSpan(ctx, operation)
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

func (n *noopImpl) StartSpan(ctx context.Context, _ string) {
	n.ctx = ctx
}
func (n *noopImpl) StartChildSpan(_ string)  {}
func (n *noopImpl) Finish()                  {}
func (n *noopImpl) Context() context.Context { return n.ctx }
