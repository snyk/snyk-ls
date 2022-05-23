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

type spanImpl struct {
	span *sentry.Span
}

func (s *spanImpl) StartSpan(ctx context.Context, operation string) {
	s.span = sentry.StartSpan(ctx, operation)
}

func (s *spanImpl) Finish() {
	s.span.Finish()
}

func (s *spanImpl) Context() context.Context {
	return s.span.Context()
}

func New() Span {
	if config.CurrentConfig().IsTelemetryEnabled() {
		return &spanImpl{}
	}
	return &noopImpl{}
}

func (n *noopImpl) StartSpan(ctx context.Context, _ string) {
	n.ctx = ctx
}
func (n *noopImpl) StartChildSpan(_ string)  {}
func (n *noopImpl) Finish()                  {}
func (n *noopImpl) Context() context.Context { return n.ctx }
