package performance

import (
	"context"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type NoopSpan struct {
	Operation string
	TxName    string
	Started   bool
	Finished  bool
	ctx       context.Context
}

func (n *NoopSpan) Finish() {
	n.Started = false
	n.Finished = true
	log.Trace().
		Str("method", "NoopSpan.Finish").
		Str("operation", n.Operation).
		Msg("finishing span")
}

func (n *NoopSpan) SetTransactionName(txName string) { n.TxName = txName }
func (n *NoopSpan) StartSpan(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	log.Trace().
		Str("method", "NoopSpan.StartSpan").
		Str("operation", n.Operation).
		Msg("starting span")
	n.ctx = GetContextWithTraceId(ctx, uuid.New().String())
	n.Started = true
}

func (n *NoopSpan) GetOperation() string {
	return n.Operation
}
func (n *NoopSpan) GetTxName() string {
	return n.TxName
}
func (n *NoopSpan) GetTraceId() string {
	return n.ctx.Value(TraceIdContextKey("trace_id")).(string)
}
func (n *NoopSpan) Context() context.Context {
	return n.ctx
}
