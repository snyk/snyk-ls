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

func ExternalIcon() template.HTML {
	return template.HTML(`<svg class="is-external-icon" width="9" height="9" viewBox="0 0 9 9" xmlns="http://www.w3.org/2000/svg" fill="none">
		<path d="M4.99998 0L6.64648 1.6465L3.14648 5.1465L3.85348 5.8535L7.35348 2.3535L8.99998 4V0H4.99998Z" fill="#888"/>
		<path d="M8 8H1V1H4.5L3.5 0H1C0.4485 0 0 0.4485 0 1V8C0 8.5515 0.4485 9 1 9H8C8.5515 9 9 8.5515 9 8V5.5L8 4.5V8Z" fill="#888"/>
	</svg>`)
}
