package performance

import "context"

type Instrumentor interface {
	StartSpan(ctx context.Context, operation string) Span
	NewTransaction(ctx context.Context, txName string, operation string) Span
	Finish(span Span)
	CreateSpan(txName string, operation string) Span
}

type Span interface {
	SetTransactionName(name string)
	StartSpan(ctx context.Context)
	Finish()
	GetOperation() string
	GetTxName() string
	Context() context.Context
}
