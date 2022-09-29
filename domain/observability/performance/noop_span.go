/*
 * Copyright 2022 Snyk Ltd.
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

	"github.com/google/uuid"
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
}

func (n *NoopSpan) SetTransactionName(txName string) { n.TxName = txName }
func (n *NoopSpan) StartSpan(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
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
