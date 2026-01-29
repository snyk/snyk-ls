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
	Duration          time.Duration
	TimestampFinished time.Time
	Path              FilePath
	IsDeltaScan       bool
	SendAnalytics     bool
	UpdateGlobalCache bool
}

type Scanner interface {
	// Scan scans a workspace folder or file for issues.
	// - objectToScan: The target file or folder to scan. If blank or equal to workspaceFolderConfig.FolderPath,
	//   a full workspace scan is performed.
	// - workspaceFolderConfig: The workspace folder configuration, providing org settings and scan context.
	Scan(ctx context.Context, objectToScan FilePath, processResults ScanResultProcessor, workspaceFolderConfig *FolderConfig)
}

//go:generate go tool github.com/golang/mock/mockgen -source=scan.go -destination mock_types/scan_mock.go -package mock_types

type ProductScanner interface {
	// Scan scans a workspace folder or file for issues.
	// - objectToScan: The target file or folder to scan. If blank or equal to workspaceFolderConfig.FolderPath,
	//   a full workspace scan is performed.
	// - workspaceFolderConfig: The workspace folder configuration, providing org settings and scan context.
	Scan(ctx context.Context, objectToScan FilePath, workspaceFolderConfig *FolderConfig) (issues []Issue, err error)
	IsEnabled() bool
	Product() product.Product
}
