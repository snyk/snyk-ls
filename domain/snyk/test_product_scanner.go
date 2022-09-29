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

package snyk

import (
	"context"
	"sync"
	"time"

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
	product      Product
	enabled      bool
	scans        int
	mutex        sync.Mutex
	scanDuration time.Duration
}

func (t *TestProductScanner) Scan(ctx context.Context, _ string, _ string) (issues []Issue) {
	log.Debug().Msg("Test product scanner running scan")
	defer log.Debug().Msg("Test product scanner scan finished")

	// Checking for cancellation before the select statement, because if both cases are available
	// (scanDuration passed & context is done) then one of the cases will be picked at random.
	// This can happen if scanDuration is 0 and ctx.Done()
	if ctx.Err() != nil {
		log.Debug().Msg("Received cancellation signal - cancelling scan")
		return issues
	}

	select {
	case <-ctx.Done():
		log.Debug().Msg("Received cancellation signal - cancelling scan")
		return issues
	case <-time.After(t.scanDuration):
	}

	// Scan finished successfully, increase counter
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

func (t *TestProductScanner) SetScanDuration(duration time.Duration) { t.scanDuration = duration }
