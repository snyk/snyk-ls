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

package snyk

import (
	"time"

	"github.com/snyk/snyk-ls/internal/product"
)

type ScanData struct {
	Product           product.Product
	Issues            []Issue
	Err               error
	DurationMs        int64
	TimestampFinished time.Time
	Critical          int
	High              int
	Medium            int
	Low               int
	SeverityCount     map[product.Product]SeverityCount
}

type SeverityCount struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

type ScanResultProcessor = func(scanData ScanData)

//type ScanResultProcessor = func(product product.Product, issues []Issue, err error)

func NoopResultProcessor(_ ScanData) {}
