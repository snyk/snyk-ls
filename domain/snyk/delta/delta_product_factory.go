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

package delta

import (
	"github.com/snyk/snyk-ls/internal/delta"
	"github.com/snyk/snyk-ls/internal/product"
)

func NewDeltaFinderForProduct(p product.Product) *delta.Finder {
	switch p {
	case product.ProductCode:
		return delta.NewFinder(
			delta.WithEnricher(delta.NewFindingsEnricher()),
			delta.WithMatcher(delta.NewCodeMatcher()),
			delta.WithDiffer(delta.NewFindingsDiffer()))
	case product.ProductOpenSource:
		return delta.NewFinder(
			delta.WithEnricher(delta.NewFindingsEnricher()),
			delta.WithMatcher(delta.NewCodeMatcher()),
			delta.WithDiffer(delta.NewFindingsDiffer()))
	case product.ProductInfrastructureAsCode:
		return delta.NewFinder(
			delta.WithEnricher(delta.NewFindingsEnricher()),
			delta.WithMatcher(delta.NewCodeMatcher()),
			delta.WithDiffer(delta.NewFindingsDiffer()))
	default:
		return delta.NewFinder(delta.WithDiffer(delta.NewFindingsDiffer()))
	}
}
