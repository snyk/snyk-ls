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

	codeClient "github.com/snyk/code-client-go/observability"
)

type spanRecorderImplNew struct {
	mutex sync.Mutex
	spans []codeClient.Span
}

func newSpanRecorderNew() SpanRecorderNew {
	return &spanRecorderImplNew{mutex: sync.Mutex{}, spans: []codeClient.Span{}}
}

func (s *spanRecorderImplNew) Record(span codeClient.Span) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spans = append(s.spans, span)
}

func (s *spanRecorderImplNew) Spans() []codeClient.Span {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.spans
}

func (s *spanRecorderImplNew) ClearSpans() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spans = []codeClient.Span{}
}

func (s *spanRecorderImplNew) Finish(span codeClient.Span) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, currSpan := range s.spans {
		if span == currSpan {
			currSpan.Finish()
		}
	}
}

type localInstrumentorNew struct {
	SpanRecorder SpanRecorderNew
}

type SpanRecorderNew interface {
	Record(span codeClient.Span)
	Spans() []codeClient.Span
	ClearSpans()
	Finish(span codeClient.Span)
}

func NewCodeClientInstrumentor() codeClient.Instrumentor {
	return &localInstrumentorNew{SpanRecorder: newSpanRecorderNew()}
}

func (i *localInstrumentorNew) Record(span codeClient.Span) {
	i.SpanRecorder.Record(span)
}

func (i *localInstrumentorNew) Spans() []codeClient.Span {
	return i.SpanRecorder.Spans()
}

func (i *localInstrumentorNew) ClearSpans() {
	i.SpanRecorder.ClearSpans()
}

func (i *localInstrumentorNew) StartSpan(ctx context.Context, operation string) codeClient.Span {
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

func (i *localInstrumentorNew) NewTransaction(ctx context.Context, txName string, operation string) codeClient.Span {
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

func (i *localInstrumentorNew) Finish(span codeClient.Span) {
	i.SpanRecorder.Finish(span)
}
