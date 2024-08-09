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

	"github.com/snyk/snyk-ls/domain/snyk"
)

func SeverityIcon(issue snyk.Issue) template.HTML {
	switch issue.Severity {
	case snyk.Critical:
		return template.HTML(`<svg id="severity-icon" class="icon critical" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			 <rect width="16" height="16" rx="2" fill="#AB1A1A"/>
			 <path d="M9.975 9.64h2.011a3.603 3.603 0 0 1-.545 1.743 3.24 3.24 0 0 1-1.338 1.19c-.57.284-1.256.427-2.06.427-.627 0-1.19-.107-1.688-.32a3.594 3.594 0 0 1-1.278-.936 4.158 4.158 0 0 1-.801-1.47C4.092 9.7 4 9.057 4 8.345v-.675c0-.712.094-1.356.283-1.93a4.255 4.255 0 0 1 .82-1.476 3.657 3.657 0 0 1 1.286-.936A4.114 4.114 0 0 1 8.057 3c.817 0 1.505.147 2.066.44.565.295 1.002.7 1.312 1.217.314.516.502 1.104.565 1.763H9.982c-.023-.392-.101-.723-.236-.995a1.331 1.331 0 0 0-.612-.621c-.27-.143-.628-.214-1.077-.214-.336 0-.63.062-.881.187a1.632 1.632 0 0 0-.633.568c-.17.254-.298.574-.383.962a6.61 6.61 0 0 0-.121 1.349v.688c0 .503.038.946.114 1.33.076.378.193.699.35.961.161.259.368.454.619.588.256.13.563.194.922.194.421 0 .769-.067 1.043-.2a1.39 1.39 0 0 0 .625-.595c.148-.263.236-.59.263-.982Z" fill="#fff"/>
		 </svg>`)
	case snyk.High:
		return template.HTML(`<svg id="severity-icon" class="icon high" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			 <rect width="16" height="16" rx="2" fill="#CE5019"/>
			 <path d="M10.5 7v2h-5V7h5ZM6 3v10H4V3h2Zm6 0v10h-2V3h2Z" fill="#fff"/>
		 </svg>`)
	case snyk.Medium:
		return template.HTML(`<svg id="severity-icon" class="icon medium" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			 <rect width="16" height="16" rx="2" fill="#D68000"/>
			 <path d="M3 3h2l2.997 7.607L11 3h2L9 13H7L3 3Zm0 0h2v10l-2-.001V3.001Zm8 0h2V13h-2V3Z" fill="#fff"/>
		 </svg>`)
	case snyk.Low:
		return template.HTML(`<svg id="severity-icon" class="icon low" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			 <rect width="16" height="16" rx="2" fill="#88879E"/>
			 <path d="M11 11v2H6.705v-2H11ZM7 3v10H5V3h2Z" fill="#fff"/>
		 </svg>`)
	default:
		return ``
	}
}
