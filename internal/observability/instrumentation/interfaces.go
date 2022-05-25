package instrumentation

import "context"

type Instrumentor interface {
	StartSpan(ctx context.Context, operation string) Span
	NewTransaction(ctx context.Context, txName string, operation string) Span
	Finish(span Span)
	CreateSpan(ctx context.Context, txName string, operation string) Span
}

type Span interface {
	Context() context.Context
	SetTransactionName(name string)
	StartSpan()
	Finish()
	GetOperation() string
	GetTxName() string
}
