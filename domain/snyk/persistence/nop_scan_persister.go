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
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

var _ ScanSnapshotPersister = (*NopScanPersister)(nil)

type NopScanPersister struct {
}

func NewNopScanPersister() *NopScanPersister {
	return &NopScanPersister{}
}

func (n NopScanPersister) Exists(_ types.FilePath, _ string, _ product.Product) bool {
	return false
}

func (n NopScanPersister) Clear(_ []types.FilePath, _ bool) {
}

func (n NopScanPersister) Init(folderPath []types.FilePath) error {
	return nil
}

func (n NopScanPersister) Add(_ types.FilePath, _ string, _ []types.Issue, _ product.Product) error {
	return nil
}

func (n NopScanPersister) GetPersistedIssueList(_ types.FilePath, _ product.Product) ([]types.Issue, error) {
	return nil, nil
}
