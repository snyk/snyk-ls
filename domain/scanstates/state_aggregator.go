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

type Aggregator interface {
	Init(folders []types.FilePath)
	AddNewFolder(folderPath types.FilePath)
	SetScanState(folderPath types.FilePath, p product.Product, isReferenceScan bool, newState scanState)
	SetScanDone(folderPath types.FilePath, p product.Product, isReferenceScan bool, scanErr error)
	SetScanInProgress(folderPath types.FilePath, p product.Product, isReferenceScan bool)
	allScansStarted(isReference bool) bool
	anyScanInProgress(isReference bool) bool
	anyScanSucceeded(isReference bool) bool
	allScansSucceeded(isReference bool) bool
	anyScanError(isReference bool) bool
	SummaryEmitter() ScanStateChangeEmitter
	StateSnapshot() StateSnapshot
	GetScanErr(folderPath types.FilePath, p product.Product, isReferenceScan bool) error
}
