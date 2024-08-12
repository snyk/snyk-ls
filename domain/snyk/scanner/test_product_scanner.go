/*
 * © 2022-2024 Snyk Limited
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

package scanner

import (
	"context"
	"github.com/snyk/snyk-ls/domain/snyk"
	"sync"
	"time"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/product"
)

func NewTestProductScanner(product product.Product, enabled bool) *TestProductScanner {
	return &TestProductScanner{
		product: product,
		enabled: enabled,
		scans:   0,
		mutex:   sync.Mutex{},
		c:       config.CurrentConfig(),
	}
}

type TestProductScanner struct {
	product      product.Product
	enabled      bool
	scans        int
	mutex        sync.Mutex
	scanDuration time.Duration
	c            *config.Config
}

func (t *TestProductScanner) GetInlineValues(_ string, _ snyk.Range) ([]snyk.InlineValue, error) {
	return []snyk.InlineValue{}, nil
}

func (t *TestProductScanner) Scan(ctx context.Context, _ string, _ string) (issues []snyk.Issue, err error) {
	t.c.Logger().Debug().Msg("Test product scanner running scan")
	defer t.c.Logger().Debug().Msg("Test product scanner scan finished")

	// Checking for cancellation before the select statement, because if both cases are available
	// (scanDuration passed & context is done) then one of the cases will be picked at random.
	// This can happen if scanDuration is 0 and ctx.Done()
	if ctx.Err() != nil {
		t.c.Logger().Debug().Msg("Received cancellation signal - canceling scan")
		return issues, nil
	}

	select {
	case <-ctx.Done():
		t.c.Logger().Debug().Msg("Received cancellation signal - canceling scan")
		return issues, nil
	case <-time.After(t.scanDuration):
	}

	// Scan finished successfully, increase counter
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.scans++
	return []snyk.Issue{}, nil
}

func (t *TestProductScanner) Scans() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.scans
}

func (t *TestProductScanner) IsEnabled() bool {
	return t.enabled
}

func (t *TestProductScanner) Product() product.Product {
	return t.product
}

func (t *TestProductScanner) SetScanDuration(duration time.Duration) { t.scanDuration = duration }
