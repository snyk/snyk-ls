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

package lsp

// TODO: this belongs to Snyk domain but has to live here until there's no dependency on lsp from the domain layer.

func NewSeverityFilter(critical bool, high bool, medium bool, low bool) SeverityFilter {
	return SeverityFilter{
		Critical: critical,
		High:     high,
		Medium:   medium,
		Low:      low,
	}
}

func DefaultSeverityFilter() SeverityFilter {
	return SeverityFilter{
		Critical: true,
		High:     true,
		Medium:   true,
		Low:      true,
	}
}
