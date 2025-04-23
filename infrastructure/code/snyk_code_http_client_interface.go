/*
 * © 2022-2024 Snyk Limited
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

package code

import (
	"context"

	"github.com/snyk/snyk-ls/internal/types"
)

type AnalysisOptions struct {
	bundleHash   string
	shardKey     string
	limitToFiles []types.FilePath
	severity     int
}

type AutofixOptions struct {
	bundleHash string
	shardKey   string
	filePath   types.FilePath
	issue      types.Issue
}

type SnykCodeClient interface {
	GetFilters(ctx context.Context) (
		filters FiltersResponse,
		err error)

	CreateBundle(
		ctx context.Context,
		files map[types.FilePath]string,
	) (newBundleHash string, missingFiles []types.FilePath, err error)

	ExtendBundle(ctx context.Context, bundleHash string, files map[types.FilePath]BundleFile, removedFiles []types.FilePath) (newBundleHash string, missingFiles []types.FilePath, err error)

	RunAnalysis(
		ctx context.Context,
		options AnalysisOptions,
		baseDir types.FilePath,
	) (
		[]types.Issue,
		AnalysisStatus,
		error,
	)

	SubmitAutofixFeedback(ctx context.Context, fixId string, result string) error
}
