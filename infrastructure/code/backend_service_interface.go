/*
 * © 2022 Snyk Limited All rights reserved.
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

	"github.com/snyk/snyk-ls/domain/snyk"
)

type AnalysisOptions struct {
	bundleHash   string
	shardKey     string
	limitToFiles []string
	severity     int
}

type AutofixOptions struct {
	bundleHash string
	shardKey   string
	filePath   string
	issue      snyk.Issue
}

type SnykCodeClient interface {
	GetFilters(ctx context.Context) (configFiles []string, extensions []string, err error)

	CreateBundle(
		ctx context.Context,
		files map[string]string,
	) (newBundleHash string, missingFiles []string, err error)

	ExtendBundle(
		ctx context.Context,
		bundleHash string,
		files map[string]BundleFile,
		removedFiles []string,
	) (newBundleHash string, missingFiles []string, err error)

	RunAnalysis(
		ctx context.Context,
		options AnalysisOptions,
	) (
		[]snyk.Issue,
		AnalysisStatus,
		error,
	)

	RunAutofix(
		ctx context.Context,
		options AutofixOptions,
	) ([]snyk.AutofixSuggestion,
		AutofixStatus,
		error,
	)
}
