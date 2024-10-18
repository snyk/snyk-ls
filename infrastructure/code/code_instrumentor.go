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

package code

import (
	"context"
	"sync"

	codeClient "github.com/snyk/code-client-go/observability"

	"github.com/snyk/snyk-ls/internal/observability/performance"
)

type spanRecorderCodeImpl struct {
	mutex sync.Mutex
	spans []codeClient.Span
}

func newSpanRecorderNew() SpanRecorderCode {
	return &spanRecorderCodeImpl{mutex: sync.Mutex{}, spans: []codeClient.Span{}}
}

func (s *spanRecorderCodeImpl) Record(span codeClient.Span) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spans = append(s.spans, span)
}

func (s *spanRecorderCodeImpl) Spans() []codeClient.Span {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.spans
}

func (s *spanRecorderCodeImpl) ClearSpans() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spans = []codeClient.Span{}
}

func (s *spanRecorderCodeImpl) Finish(span codeClient.Span) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, currSpan := range s.spans {
		if span == currSpan {
			currSpan.Finish()
		}
	}
}

type codeInstrumentor struct {
	SpanRecorder SpanRecorderCode
}

type SpanRecorderCode interface {
	Record(span codeClient.Span)
	Spans() []codeClient.Span
	ClearSpans()
	Finish(span codeClient.Span)
}

func NewCodeInstrumentor() codeClient.Instrumentor {
	return &codeInstrumentor{SpanRecorder: newSpanRecorderNew()}
}

func (i *codeInstrumentor) Record(span codeClient.Span) {
	i.SpanRecorder.Record(span)
}

func (i *codeInstrumentor) Spans() []codeClient.Span {
	return i.SpanRecorder.Spans()
}

func (i *codeInstrumentor) ClearSpans() {
	i.SpanRecorder.ClearSpans()
}

func (i *codeInstrumentor) StartSpan(ctx context.Context, operation string) codeClient.Span {
	span := performance.NewNoopSpan(ctx, operation, "", false, false)
	span.StartSpan(ctx)
	i.SpanRecorder.Record(span)
	return span
}

func (i *codeInstrumentor) NewTransaction(ctx context.Context, txName string, operation string) codeClient.Span {
	s := performance.NewNoopSpan(ctx, operation, txName, false, false)
	i.SpanRecorder.Record(s)
	return s
}

func (i *codeInstrumentor) Finish(span codeClient.Span) {
	i.SpanRecorder.Finish(span)
}
