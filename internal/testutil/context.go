/*
 * © 2026 Snyk Limited
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

package testutil

import (
	"context"
	"testing"

	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/types"
)

// FolderScanContextOption configures a folder scan context.
type FolderScanContextOption func(context.Context) context.Context

// WithScanType adds a delta scan type to a folder scan context.
func WithScanType(scanType ctx2.DeltaScanType) FolderScanContextOption {
	return func(ctx context.Context) context.Context {
		return ctx2.NewContextWithDeltaScanType(ctx, scanType)
	}
}

// ContextWithFolderScan returns a context carrying folderPath's FolderConfig and ConfigResolver.
func ContextWithFolderScan(
	t *testing.T,
	resolver *types.ConfigResolver,
	folderPath types.FilePath,
	options ...FolderScanContextOption,
) context.Context {
	t.Helper()
	ctx := ctx2.NewContextWithConfigResolver(t.Context(), resolver)
	ctx = ctx2.NewContextWithFolderConfig(ctx, &types.FolderConfig{
		FolderPath:     folderPath,
		ConfigResolver: resolver,
	})
	for _, option := range options {
		ctx = option(ctx)
	}
	return ctx
}
