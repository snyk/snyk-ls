/*
 * © 2022-2023 Snyk Limited
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

type SeverityFilter struct {
	Critical bool `json:"critical,omitempty"`
	High     bool `json:"high,omitempty"`
	Medium   bool `json:"medium,omitempty"`
	Low      bool `json:"low,omitempty"`
}
