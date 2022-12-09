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
	"sync"
)

type SpanRecorder struct {
	mutex sync.Mutex
	spans []Span
}

func newSpanRecorder() *SpanRecorder {
	return &SpanRecorder{mutex: sync.Mutex{}, spans: []Span{}}
}

func (s *SpanRecorder) Record(span Span) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spans = append(s.spans, span)
}

func (s *SpanRecorder) Spans() []Span {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.spans
}

func (s *SpanRecorder) ClearSpans() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spans = []Span{}
}

func (s *SpanRecorder) Finish(span Span) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, currSpan := range s.spans {
		if span == currSpan {
			currSpan.Finish()
		}
	}
}

type TestInstrumentor struct {
	SpanRecorder *SpanRecorder
}

func NewTestInstrumentor() *TestInstrumentor {
	return &TestInstrumentor{SpanRecorder: newSpanRecorder()}
}

func (i *TestInstrumentor) StartSpan(ctx context.Context, operation string) Span {
	span := &NoopSpan{
		Operation: operation,
		TxName:    "",
		Started:   false,
		Finished:  false,
		ctx:       ctx,
	}
	span.StartSpan(ctx)
	i.SpanRecorder.Record(span)
	return span
}

func (i *TestInstrumentor) NewTransaction(ctx context.Context, txName string, operation string) Span {
	s := &NoopSpan{
		Operation: operation,
		TxName:    txName,
		Started:   false,
		Finished:  false,
		ctx:       ctx,
	}
	i.SpanRecorder.Record(s)
	return s
}

func (i *TestInstrumentor) Finish(span Span) {
	i.SpanRecorder.Finish(span)
}
