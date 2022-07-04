package sentry

import (
	"context"

	"github.com/snyk/snyk-ls/application/config"
	performance2 "github.com/snyk/snyk-ls/domain/observability/performance"
)

// An instrumentor that respects GDPR config (i.e. whether users want to share stats)
type gdprAwareSentryInstrumentor struct{}

func NewInstrumentor() performance2.Instrumentor {
	initializeSentry()
	return &gdprAwareSentryInstrumentor{}
}

func (i *gdprAwareSentryInstrumentor) Finish(span performance2.Span) {
	span.Finish()
}

func (i *gdprAwareSentryInstrumentor) StartSpan(ctx context.Context, operation string) performance2.Span {
	s := i.CreateSpan("", operation)
	s.StartSpan(ctx)
	return s
}

func (i *gdprAwareSentryInstrumentor) NewTransaction(ctx context.Context, txName string, operation string) performance2.Span {
	s := i.CreateSpan(txName, operation)
	s.StartSpan(ctx)
	return s
}

func (i *gdprAwareSentryInstrumentor) CreateSpan(txName string, operation string) performance2.Span {
	var s performance2.Span
	if config.CurrentConfig() != nil && config.CurrentConfig().IsTelemetryEnabled() {
		s = &span{operation: operation}
	} else {
		s = &performance2.NoopSpan{Operation: operation}
	}
	s.SetTransactionName(txName)
	return s
}
