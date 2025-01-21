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

package aggregator

import (
	"github.com/snyk/snyk-ls/internal/product"
)

var _ StateAggregator = (*NoopStateAggregator)(nil)

type NoopStateAggregator struct {
}

func (n NoopStateAggregator) Init(_ []string) {
}

func NewNoopStateAggregator() StateAggregator {
	return &NoopStateAggregator{}
}

func (n NoopStateAggregator) AddNewFolder(_ string) {
}

func (n NoopStateAggregator) SetScanState(_ string, _ product.Product, _ bool, _ ScanState) {
}

func (n NoopStateAggregator) SetScanDone(_ string, _ product.Product, _ bool, _ error) {
}

func (n NoopStateAggregator) SetScanInProgress(_ string, _ product.Product, _ bool) {
}

func (n NoopStateAggregator) AreAllScansNotStarted(_ bool) bool {
	return false
}

func (n NoopStateAggregator) HasAnyScanInProgress(_ bool) bool {
	return false
}

func (n NoopStateAggregator) HasAnyScanSucceeded(_ bool) bool {
	return false
}

func (n NoopStateAggregator) HaveAllScansSucceeded(_ bool) bool {
	return false
}

func (n NoopStateAggregator) HasAnyScanError(_ bool) bool {
	return false
}
