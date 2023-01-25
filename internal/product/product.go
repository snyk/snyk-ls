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

package product

type Product string
type ProductAttributes map[string]any
type FilterableIssueType string

const (
	ProductOpenSource           Product = "Snyk Open Source"
	ProductCode                 Product = "Snyk Code"
	ProductInfrastructureAsCode Product = "Snyk IaC"
)

const (
	FilterableIssueTypeOpenSource           FilterableIssueType = "Open Source"
	FilterableIssueTypeCodeQuality          FilterableIssueType = "Code Quality"
	FilterableIssueTypeCodeSecurity         FilterableIssueType = "Code Security"
	FilterableIssueTypeInfrastructureAsCode FilterableIssueType = "Infrastructure As Code"
)

func ToProductCodename(product Product) string {
	switch product {
	case ProductOpenSource:
		return "oss"
	case ProductCode:
		return "code"
	case ProductInfrastructureAsCode:
		return "iac"
	default:
		return "unknown"
	}
}
