package performance

import (
	"context"
	"errors"
)

type TraceIdContextKey string

// GetContextWithTraceId Returns a child context with "trace_id" set to the given traceId
func GetContextWithTraceId(ctx context.Context, traceId string) context.Context {
	return context.WithValue(ctx, TraceIdContextKey("trace_id"), traceId)
}

func GetTraceId(ctx context.Context) (string, error) {
	v, ok := ctx.Value(TraceIdContextKey("trace_id")).(string)
	if !ok {
		return "", errors.New("\"trace_id\" context key not found")
	}

	return v, nil
}
