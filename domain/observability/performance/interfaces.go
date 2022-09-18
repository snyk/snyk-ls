package performance

import "context"

type Instrumentor interface {
	StartSpan(ctx context.Context, operation string) Span
	NewTransaction(ctx context.Context, txName string, operation string) Span
	Finish(span Span)
}

type Span interface {
	SetTransactionName(name string)
	StartSpan(ctx context.Context)
	Finish()
	GetOperation() string
	GetTxName() string

	// GetTraceId Returns UUID of the trace
	GetTraceId() string
	Context() context.Context
}
