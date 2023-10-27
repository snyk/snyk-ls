/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package performance

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type NoopSpan struct {
	Operation  string
	TxName     string
	Started    bool
	Finished   bool
	ctx        context.Context
	StartTime  int64
	FinishTime int64
}

func (n *NoopSpan) GetDurationMs() int64 { return n.FinishTime - n.StartTime }

func (n *NoopSpan) Finish() {
	n.Started = false
	n.Finished = true
	n.FinishTime = time.Now().UnixMilli()
}

func (n *NoopSpan) SetTransactionName(txName string) { n.TxName = txName }
func (n *NoopSpan) StartSpan(ctx context.Context) {
	n.StartTime = time.Now().UnixMilli()
	var traceID string
	if ctx == nil {
		ctx = context.Background()
	}
	if t, ok := n.getTraceIDFromContext(ctx); ok {
		traceID = t
	} else {
		traceID = uuid.New().String()
	}
	n.ctx = GetContextWithTraceId(ctx, traceID)
	n.Started = true
}

func (n *NoopSpan) GetOperation() string {
	return n.Operation
}
func (n *NoopSpan) GetTxName() string {
	return n.TxName
}
func (n *NoopSpan) GetTraceId() string {
	t, ok := n.getTraceIDFromContext(n.ctx)
	if ok {
		return t
	}
	return ""
}

func (n *NoopSpan) getTraceIDFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(TraceIdContextKey("trace_id")).(string)
	return t, ok
}
func (n *NoopSpan) Context() context.Context {
	return n.ctx
}
