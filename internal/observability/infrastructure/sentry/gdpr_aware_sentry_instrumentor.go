package sentry

import (
	"context"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/observability/performance"
)

// An instrumentor that respects GDPR config (i.e. whether users want to share stats)
type gdprAwareSentryInstrumentor struct{}

func NewInstrumentor() performance.Instrumentor {
	initializeSentry()
	return &gdprAwareSentryInstrumentor{}
}

func (i *gdprAwareSentryInstrumentor) Finish(span performance.Span) {
	span.Finish()
}

func (i *gdprAwareSentryInstrumentor) StartSpan(ctx context.Context, operation string) performance.Span {
	s := i.CreateSpan("", operation)
	s.StartSpan(ctx)
	return s
}

func (i *gdprAwareSentryInstrumentor) NewTransaction(ctx context.Context, txName string, operation string) performance.Span {
	s := i.CreateSpan(txName, operation)
	s.StartSpan(ctx)
	return s
}

func (i *gdprAwareSentryInstrumentor) CreateSpan(txName string, operation string) performance.Span {
	var s performance.Span
	if config.CurrentConfig() != nil && config.CurrentConfig().IsTelemetryEnabled() {
		s = &span{operation: operation}
	} else {
		s = &performance.NoopSpan{Operation: operation}
	}
	s.SetTransactionName(txName)
	return s
}
