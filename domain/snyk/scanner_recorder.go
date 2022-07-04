package snyk

import (
	"context"
)

type TestScanner struct {
	Calls  int
	Issues []Issue
}

func NewTestScanner() *TestScanner {
	return &TestScanner{
		Calls:  0,
		Issues: []Issue{},
	}
}

func (s *TestScanner) IsEnabled() bool {
	return true
}

func (s *TestScanner) Scan(
	ctx context.Context,
	path string,
	processResults ScanResultProcessor,
	naughtyHack1 string,
	naughtyHack2 []string,
) {
	processResults(s.Issues)
	s.Calls++
}
