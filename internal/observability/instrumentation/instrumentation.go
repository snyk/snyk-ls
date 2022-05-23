package instrumentation

import (
	"context"

	"github.com/getsentry/sentry-go"
)

type Span interface {
	StartSpan(ctx context.Context, name string)
	StartChildSpan(name string)
	Finish()
	Context() context.Context
}

type spanImpl struct {
	span *sentry.Span
}

func (t *spanImpl) StartSpan(ctx context.Context, operation string) {
	t.span = sentry.StartSpan(ctx, operation)
}

func (t *spanImpl) Finish() {
	t.span.Finish()
}

func (t *spanImpl) Context() context.Context {
	return t.span.Context()
}

func New() *spanImpl {
	return &spanImpl{}
}
