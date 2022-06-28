package performance

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetContextWithTraceId(t *testing.T) {
	t.Run("sets trace_id", func(t *testing.T) {
		// prepare
		ctx := context.Background()
		uuid := uuid.New().String()

		// act
		newCtx := GetContextWithTraceId(ctx, uuid)

		// assert
		traceId, err := GetTraceId(newCtx)
		if err != nil {
			assert.Fail(t, "Couldn't obtain trace_id")
		}

		assert.Equal(t, traceId, uuid)
	})
}
