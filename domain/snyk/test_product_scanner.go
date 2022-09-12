package snyk

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"
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

func (t *TestProductScanner) Scan(ctx context.Context, _ string, _ string) (issues []Issue) {
	if ctx.Err() != nil {
		log.Debug().Msg("Received cancellation signal - cancelling scan")
		return issues
	}

	log.Debug().Msg("Test product scanner running scan")
	defer log.Debug().Msg("Test product scanner scan finished")
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
