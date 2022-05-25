package instrumentation

import (
	"context"

	"github.com/snyk/snyk-ls/config"
)

type InstrumentorImpl struct{}

func (i *InstrumentorImpl) Finish(span Span) {
	span.Finish()
}

func (i *InstrumentorImpl) StartSpan(ctx context.Context, operation string) Span {
	s := i.CreateSpan("", operation)
	s.StartSpan(ctx)
	return s
}

func (i *InstrumentorImpl) NewTransaction(ctx context.Context, txName string, operation string) Span {
	s := i.CreateSpan(txName, operation)
	s.StartSpan(ctx)
	return s
}

func (i *InstrumentorImpl) CreateSpan(txName string, operation string) Span {
	var s Span
	if config.CurrentConfig() != nil && config.CurrentConfig().IsTelemetryEnabled() {
		s = &sentrySpan{operation: operation}
	} else {
		s = &noopSpan{operation: operation}
	}
	s.SetTransactionName(txName)
	return s
}
