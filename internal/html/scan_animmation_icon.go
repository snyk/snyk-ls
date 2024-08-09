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

func ScanAnimation() template.HTML {
	return template.HTML(`<svg id="scan-animation" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 248 204" shape-rendering="geometricPrecision">
	<defs>
		<linearGradient id="mg" x1="16.0903" y1="180" x2="92.743" y2="107.462" spreadMethod="pad"
			gradientUnits="userSpaceOnUse" gradientTransform="translate(0 0)">
			<stop id="eQeHIUZsTfX2-fill-0" offset="0%" stop-color="#145deb" />
			<stop id="eQeHIUZsTfX2-fill-1" offset="100%" stop-color="#441c99" />
		</linearGradient>
		<linearGradient id="sg" x1="116" y1="0" x2="116" y2="64" spreadMethod="pad" gradientUnits="userSpaceOnUse"
			gradientTransform="translate(0 0)">
			<stop id="eQeHIUZsTfX26-fill-0" offset="0%" stop-color="#ff78e1" />
			<stop id="eQeHIUZsTfX26-fill-1" offset="100%" stop-color="rgba(255,120,225,0)" />
		</linearGradient>
	</defs>
	<rect width="224" height="180" rx="16" ry="16" transform="translate(12 12)" fill="url(#mg)" />
	<circle r="4" transform="translate(28 28)" opacity="0.3" fill="#fff" />
	<circle r="4" transform="translate(40 28)" opacity="0.25" fill="#fff" />
	<circle r="4" transform="translate(52 28)" opacity="0.2" fill="#fff" />
	<rect width="48" height="12" rx="6" ry="6" transform="translate(162 56)" opacity="0.2" fill="#fff" />
	<rect width="80" height="12" rx="6" ry="6" transform="translate(32 92)" opacity="0.2" fill="#fff" />
	<rect width="72" height="12" rx="6" ry="6" transform="translate(96 164)" opacity="0.2" fill="#fff" />
	<rect width="56" height="12" rx="6" ry="6" transform="translate(156 128)" opacity="0.2" fill="#fff" />
	<rect id="l3" width="80" height="12" rx="6" ry="6" transform="translate(64 128)" />
	<rect id="l2" width="64" height="12" rx="6" ry="6" transform="translate(150 92)" />
	<rect id="l1" width="117" height="12" rx="6" ry="6" transform="translate(32 56)" />
	<g id="b3">
		<rect width="32" height="32" rx="6" ry="6" transform="translate(48 118)" fill="#43b59a" />
		<path
			d="M54.5991,134c.7987-.816,2.0938-.816,2.8926,0l2.8926,2.955l10.124-10.343c.7988-.816,2.0939-.816,2.8926,0c.7988.816.7988,2.139,0,2.955L61.8306,141.388c-.7988.816-2.0939.816-2.8926,0l-4.3389-4.433c-.7988-.816-.7988-2.139,0-2.955Z"
			fill="#fff" />
	</g>
	<g id="b2">
		<rect width="32" height="32" rx="6" ry="6" transform="translate(124 81)" fill="#f97a99" />
		<path
			d="M142,91c0,.7685-.433,5.3087-1.069,8h-1.862c-.636-2.6913-1.069-7.2315-1.069-8c0-1.1046.895-2,2-2s2,.8954,2,2Z"
			fill="#fff" />
		<path d="M140,104c1.105,0,2-.895,2-2s-.895-2-2-2-2,.895-2,2s.895,2,2,2Z" fill="#fff" />
	</g>
	<g id="b1">
		<rect width="24" height="24" rx="6" ry="6" transform="translate(28 50)" fill="#f97a99" />
		<path
			d="M42,56c0,.7685-.4335,5.3087-1.0693,8h-1.8614C38.4335,61.3087,38,56.7685,38,56c0-1.1046.8954-2,2-2s2,.8954,2,2Z"
			fill="#fff" />
		<path d="M40,69c1.1046,0,2-.8954,2-2s-.8954-2-2-2-2,.8954-2,2s.8954,2,2,2Z" fill="#fff" />
	</g>
	<g id="s0" transform="translate(124,-40)">
		<g transform="translate(-124,-40)">
			<rect width="232" height="64" rx="0" ry="0" transform="matrix(1 0 0-1 8 64)" opacity="0.5" fill="url(#sg)" />
			<rect width="248" height="16" rx="8" ry="8" transform="translate(0 64)" fill="#e555ac" />
		</g>
	</g>
	</svg>`)
}
