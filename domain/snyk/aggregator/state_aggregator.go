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

import "github.com/snyk/snyk-ls/internal/product"

type StateAggregator interface {
	AddNewFolder(folderPath string)
	SetScanState(folderPath string, p product.Product, isReferenceScan bool, newState ScanState)
	SetScanDone(folderPath string, p product.Product, isReferenceScan bool, scanErr error)
	SetScanInProgress(folderPath string, p product.Product, isReferenceScan bool)
	AreAllScansNotStarted(isReference bool) bool
	HasAnyScanInProgress(isReference bool) bool
	HasAnyScanSucceeded(isReference bool) bool
	HaveAllScansSucceeded(isReference bool) bool
	HasAnyScanError(isReference bool) bool
}
