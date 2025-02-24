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

package types

import (
	"context"
	"time"

	"github.com/snyk/snyk-ls/internal/product"
)

type ScanResultProcessor = func(ctx context.Context, scanData ScanData)

func NoopResultProcessor(_ context.Context, _ ScanData) {}

type ScanData struct {
	Product           product.Product
	Issues            []Issue
	Err               error
	DurationMs        time.Duration
	TimestampFinished time.Time
	Path              FilePath
	IsDeltaScan       bool
	SendAnalytics     bool
	UpdateGlobalCache bool
}

type Scanner interface {
	// Scan scans a workspace folder or file for issues, given its path. 'folderPath' provides a path to a workspace folder, if a file needs to be scanned.
	Scan(ctx context.Context, path FilePath, processResults ScanResultProcessor, folderPath FilePath)
}

type ProductScanner interface {
	// Scan scans a workspace folder or file for issues, given its path. 'folderPath' provides a path to a workspace folder, if a file needs to be scanned.
	Scan(ctx context.Context, path FilePath, folderPath FilePath, folderConfig *FolderConfig) (issues []Issue, err error)

	IsEnabled() bool
	Product() product.Product
}
