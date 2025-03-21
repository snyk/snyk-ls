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
	"github.com/snyk/snyk-ls/internal/types"
)

var _ Aggregator = (*NoopStateAggregator)(nil)

type NoopStateAggregator struct {
}

func (n NoopStateAggregator) GetScanErr(folderPath types.FilePath, p product.Product, isReferenceScan bool) error {
	return nil
}

func (n NoopStateAggregator) StateSnapshot() StateSnapshot {
	return StateSnapshot{}
}

func (n NoopStateAggregator) SummaryEmitter() ScanStateChangeEmitter {
	return &NoopEmitter{}
}

func (n NoopStateAggregator) Init(folders []types.FilePath) {
}

func NewNoopStateAggregator() Aggregator {
	return &NoopStateAggregator{}
}

func (n NoopStateAggregator) AddNewFolder(_ types.FilePath) {
}

func (n NoopStateAggregator) SetScanState(_ types.FilePath, _ product.Product, _ bool, _ scanState) {
}

func (n NoopStateAggregator) SetScanDone(folderPath types.FilePath, p product.Product, isReferenceScan bool, scanErr error) {
}

func (n NoopStateAggregator) SetScanInProgress(folderPath types.FilePath, p product.Product, isReferenceScan bool) {
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
