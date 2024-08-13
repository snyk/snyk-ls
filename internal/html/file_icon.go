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

import "html/template"

func FileIcon() template.HTML {
	return template.HTML(`<svg class="data-flow-file-icon" width="16" height="16" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" fill="none""><path d="M20.414,2H5V30H27V8.586ZM7,28V4H19v6h6V28Z" fill="#888"/></svg>`)
}
