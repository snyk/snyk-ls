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
	ProductContainer            Product = "Snyk Container"
	ProductUnknown              Product = ""
)

const (
	FilterableIssueTypeOpenSource           FilterableIssueType = "Open Source"
	FilterableIssueTypeCodeQuality          FilterableIssueType = "Code Quality"
	FilterableIssueTypeCodeSecurity         FilterableIssueType = "Code Security"
	FilterableIssueTypeInfrastructureAsCode FilterableIssueType = "Infrastructure As Code"
	FilterableIssueTypeContainer            FilterableIssueType = "Container"
)

func (p Product) ToProductCodename() string {
	switch p {
	case ProductOpenSource:
		return "oss"
	case ProductCode:
		return "code"
	case ProductInfrastructureAsCode:
		return "iac"
	case ProductContainer:
		return "container"
	default:
		return ""
	}
}

func (p Product) ToFilterableIssueType() []FilterableIssueType {
	switch p {
	case ProductOpenSource:
		return []FilterableIssueType{FilterableIssueTypeOpenSource}
	case ProductCode:
		return []FilterableIssueType{FilterableIssueTypeCodeQuality, FilterableIssueTypeCodeSecurity}
	case ProductInfrastructureAsCode:
		return []FilterableIssueType{FilterableIssueTypeInfrastructureAsCode}
	case ProductContainer:
		return []FilterableIssueType{FilterableIssueTypeContainer}
	default:
		return []FilterableIssueType{}
	}
}

func (f FilterableIssueType) ToProduct() Product {
	switch f {
	case FilterableIssueTypeOpenSource:
		return ProductOpenSource
	case FilterableIssueTypeCodeQuality:
		return ProductCode
	case FilterableIssueTypeCodeSecurity:
		return ProductCode
	case FilterableIssueTypeInfrastructureAsCode:
		return ProductInfrastructureAsCode
	case FilterableIssueTypeContainer:
		return ProductContainer
	default:
		return ProductUnknown
	}
}

func ToProduct(productName string) Product {
	switch productName {
	case "oss":
		return ProductOpenSource
	case "code":
		return ProductCode
	case "iac":
		return ProductInfrastructureAsCode
	case "container":
		return ProductContainer
	default:
		return ProductUnknown
	}
}
