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

func ArrowLeftDark() template.HTML {
	return template.HTML(`<svg class="arrow-icon dark-only" width="10" height="12" viewBox="0 0 10 12" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path
    d="M8.86723 11.4303L8.86721 11.4302L0.641823 6.22447L0.387031 6.62706L0.641821 6.22447C0.532336 6.15518 0.5 6.06763 0.5 6.00001C0.5 5.93239 0.532336 5.84484 0.641821 5.77555L0.641824 5.77555L8.86721 0.569741L8.86723 0.569731C9.00417 0.483055 9.17298 0.480315 9.31053 0.543871C9.44734 0.607082 9.5 0.705333 9.5 0.79421V11.2058C9.5 11.2947 9.44734 11.3929 9.31054 11.4561C9.173 11.5197 9.00418 11.5169 8.86723 11.4303Z"
    stroke="#CCCCCC" />
	</svg>`)
}

func ArrowLeftLight() template.HTML {
	return template.HTML(`<svg class="arrow-icon light-only" width="10" height="12" viewBox="0 0 10 12" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path
    d="M8.86723 11.4303L8.86721 11.4302L0.641823 6.22447L0.387031 6.62706L0.641821 6.22447C0.532336 6.15518 0.5 6.06763 0.5 6.00001C0.5 5.93239 0.532336 5.84484 0.641821 5.77555L0.641824 5.77555L8.86721 0.569741L8.86723 0.569731C9.00417 0.483055 9.17298 0.480315 9.31053 0.543871C9.44734 0.607082 9.5 0.705333 9.5 0.79421V11.2058C9.5 11.2947 9.44734 11.3929 9.31054 11.4561C9.173 11.5197 9.00418 11.5169 8.86723 11.4303Z"
    stroke="#3B3B3B" />
	</svg>`)
}

func ArrowRightDark() template.HTML {
	return template.HTML(`
	<svg class="arrow-icon dark-only" width="10" height="12" viewBox="0 0 10 12" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path
    d="M1.13277 11.4303L1.13279 11.4302L9.35818 6.22447L9.61297 6.62706L9.35818 6.22447C9.46766 6.15518 9.5 6.06763 9.5 6.00001C9.5 5.93239 9.46766 5.84484 9.35818 5.77555L9.35818 5.77555L1.13279 0.569741L1.13277 0.569731C0.995832 0.483055 0.827023 0.480315 0.689467 0.543871C0.55266 0.607082 0.5 0.705333 0.5 0.79421V11.2058C0.5 11.2947 0.552661 11.3929 0.689456 11.4561C0.827003 11.5197 0.99582 11.5169 1.13277 11.4303Z"
    stroke="#CCCCCC" />
	</svg>`)
}

func ArrowRightLight() template.HTML {
	return template.HTML(`<svg class="arrow-icon light-only" width="10" height="12" viewBox="0 0 10 12" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path
    d="M1.13277 11.4303L1.13279 11.4302L9.35818 6.22447L9.61297 6.62706L9.35818 6.22447C9.46766 6.15518 9.5 6.06763 9.5 6.00001C9.5 5.93239 9.46766 5.84484 9.35818 5.77555L9.35818 5.77555L1.13279 0.569741L1.13277 0.569731C0.995832 0.483055 0.827023 0.480315 0.689467 0.543871C0.55266 0.607082 0.5 0.705333 0.5 0.79421V11.2058C0.5 11.2947 0.552661 11.3929 0.689456 11.4561C0.827003 11.5197 0.99582 11.5169 1.13277 11.4303Z"
    stroke="#3B3B3B" />
	</svg>`)
}
