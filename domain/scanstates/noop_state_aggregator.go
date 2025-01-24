/*
 * © 2025 Snyk Limited
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

package scanstates

import (
	"github.com/snyk/snyk-ls/internal/product"
)

var _ Aggregator = (*NoopStateAggregator)(nil)

type NoopStateAggregator struct {
}

func (n NoopStateAggregator) StateSnapshot() StateSnapshot {
	return StateSnapshot{}
}

func (n NoopStateAggregator) SummaryEmitter() ScanStateChangeEmitter {
	return &NoopEmitter{}
}

func (n NoopStateAggregator) Init(_ []string) {
}

func NewNoopStateAggregator() Aggregator {
	return &NoopStateAggregator{}
}

func (n NoopStateAggregator) AddNewFolder(_ string) {
}

func (n NoopStateAggregator) SetScanState(_ string, _ product.Product, _ bool, _ scanState) {
}

func (n NoopStateAggregator) SetScanDone(_ string, _ product.Product, _ bool, _ error) {
}

func (n NoopStateAggregator) SetScanInProgress(_ string, _ product.Product, _ bool) {
}

func (n NoopStateAggregator) allScansStarted(_ bool) bool {
	return false
}

func (n NoopStateAggregator) anyScanInProgress(_ bool) bool {
	return false
}

func (n NoopStateAggregator) anyScanSucceeded(_ bool) bool {
	return false
}

func (n NoopStateAggregator) allScansSucceeded(_ bool) bool {
	return false
}

func (n NoopStateAggregator) anyScanError(_ bool) bool {
	return false
}
