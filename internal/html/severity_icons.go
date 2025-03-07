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

package html

import (
	"html/template"

	"github.com/snyk/snyk-ls/internal/types"
)

func SeverityIcon(issue types.Issue) template.HTML {
	switch issue.GetSeverity() {
	case types.Critical:
		 return template.HTML(`<svg id="severity-icon" class="severity-icon critical" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="16" cy="16" r="16" fill="#AB1A1A"/><path d="M16.1752 11C17.98 11 19.5173 12.0972 20.1001 13.6333L21.9989 13.0004C21.1514 10.6698 18.8639 9 16.1752 9C12.7648 9 10.0001 11.6863 10.0001 15V17C10.0001 20.3137 12.7648 23 16.175 23C18.8639 23 21.1514 21.3302 21.9989 18.9996L20.1001 18.3667C19.5173 19.9028 17.98 21 16.175 21C16.172 21 16.1689 21 16.1659 21C13.8641 20.9956 12.0001 19.2064 12.0001 17V15C12.0001 12.7909 13.8694 11 16.1752 11Z" fill="white"/></svg>`)
	case types.High:
		return template.HTML(`<svg id="severity-icon" class="severity-icon high" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="16" cy="16" r="16" fill="#D93600"/><path d="M11 10H13V15H19V10H21V22H19V17H13V22H11V10Z" fill="white"/></svg>`)
	case types.Medium:
		return template.HTML(`<svg id="severity-icon" class="severity-icon medium" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="16" cy="16" r="16" fill="#D68000"/><path d="M19.996 10H22.0002V22H20.0002V15.0058L16.9591 22H15.0408L12.0002 15.0071V22H10.0002L10 10L12.0002 10L12.004 10L16 19.1902L19.996 10Z" fill="white"/></svg>`)
	case types.Low:
		return template.HTML(`<svg id="severity-icon" class="severity-icon low" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="16" cy="16" r="16" fill="#88879E"/><path d="M14 10H12V22H21V20H14V10Z" fill="white"/></svg>`)
	default:
		return ``
	}
}
