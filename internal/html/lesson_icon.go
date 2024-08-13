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

func LessonIcon() template.HTML {
	return template.HTML(`<svg class="icon" width="17" height="14" viewBox="0 0 17 14" fill="none" xmlns="http://www.w3.org/2000/svg">
	<path d="M8.25 0L0 4.5L3 6.135V10.635L8.25 13.5L13.5 10.635V6.135L15 5.3175V10.5H16.5V4.5L8.25 0ZM13.365 4.5L8.25 7.29L3.135 4.5L8.25 1.71L13.365 4.5ZM12 9.75L8.25 11.79L4.5 9.75V6.9525L8.25 9L12 6.9525V9.75Z" fill="#888"/>
	</svg>
	`)
}
