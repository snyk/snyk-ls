/*
 * © 2024 Snyk Limited
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

package persistence

import (
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
)

var _ ScanSnapshotPersister = (*NopScanPersister)(nil)

type NopScanPersister struct {
}

func NewNopScanPersister() *NopScanPersister {
	return &NopScanPersister{}
}

func (n NopScanPersister) SnapshotExists(_, _ string, _ product.Product) bool {
	return false
}

func (n NopScanPersister) Clear() {
}

func (n NopScanPersister) ClearForProduct(_ string, _ product.Product) {
}

func (n NopScanPersister) Init() {
}

func (n NopScanPersister) Add(_, _ string, _ []snyk.Issue, _ product.Product) error {
	return nil
}

func (n NopScanPersister) GetPersistedIssueList(_ string, _ product.Product) ([]snyk.Issue, error) {
	return nil, nil
}
