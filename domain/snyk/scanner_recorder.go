package snyk

import (
	"context"
	"sync"
)

type TestScanner struct {
	mutex  sync.Mutex
	calls  int
	Issues []Issue
}

func NewTestScanner() *TestScanner {
	return &TestScanner{
		calls:  0,
		Issues: []Issue{},
	}
}

func (s *TestScanner) IsEnabled() bool {
	return true
}

const TestProduct Product = "Test Product"

func (s *TestScanner) Product() Product {
	return TestProduct
}

func (s *TestScanner) Scan(
	ctx context.Context,
	path string,
	processResults ScanResultProcessor,
	naughtyHack1 string,
	naughtyHack2 []string,
) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	processResults(s.Issues)
	s.calls++
}

func (s *TestScanner) Calls() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.calls
}
