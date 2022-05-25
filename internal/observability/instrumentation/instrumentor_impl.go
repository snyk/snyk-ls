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
	s := i.CreateSpan(ctx, "", operation)
	s.StartSpan()
	return s
}

func (i *InstrumentorImpl) NewTransaction(ctx context.Context, txName string, operation string) Span {
	s := i.CreateSpan(ctx, txName, operation)
	return s
}

func (i *InstrumentorImpl) CreateSpan(ctx context.Context, txName string, operation string) Span {
	var s Span
	if config.CurrentConfig().IsTelemetryEnabled() {
		s = &sentrySpan{ctx: ctx, operation: operation}
	} else {
		s = &noopSpan{ctx: ctx, operation: operation}
	}
	s.SetTransactionName(txName)
	return s
}
