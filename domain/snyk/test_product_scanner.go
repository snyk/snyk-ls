package snyk

import (
	"context"
	"sync"
)

func NewTestProductScanner(product Product, enabled bool) *TestProductScanner {
	return &TestProductScanner{
		product: product,
		enabled: enabled,
		scans:   0,
		mutex:   sync.Mutex{},
	}
}

type TestProductScanner struct {
	product Product
	enabled bool
	scans   int
	mutex   sync.Mutex
}

func (t *TestProductScanner) Scan(_ context.Context, _ string, _ string) (issues []Issue) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.scans++
	return []Issue{}
}

func (t *TestProductScanner) Scans() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.scans
}

func (t *TestProductScanner) IsEnabled() bool {
	return t.enabled
}

func (t *TestProductScanner) Product() Product {
	return t.product
}
