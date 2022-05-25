package performance

import (
	"context"
	"sync"
)

type SpanRecorder struct {
	mutex sync.Mutex
	spans []Span
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
	SpanRecorder SpanRecorder
}

func (i *TestInstrumentor) StartSpan(ctx context.Context, operation string) Span {
	span := i.CreateSpan("", operation)
	span.StartSpan(ctx)
	i.SpanRecorder.Record(span)
	return span
}

func (i *TestInstrumentor) NewTransaction(ctx context.Context, txName string, operation string) Span {
	s := i.CreateSpan(txName, operation)
	i.SpanRecorder.Record(s)
	return s
}

func (i *TestInstrumentor) Finish(span Span) {
	i.SpanRecorder.Finish(span)
}

func (i *TestInstrumentor) CreateSpan(txName string, operation string) Span {
	return &noopSpan{
		operation: operation,
		txName:    txName,
		started:   false,
		finished:  false,
	}
}
