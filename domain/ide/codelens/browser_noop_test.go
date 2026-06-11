/*
 * © 2026 Snyk Limited
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

// Package codelens — test-only init for DefaultOpenBrowserFunc.
// This file is compiled only into test binaries for this package.
// application/di's browser_noop_test.go does not run in this binary
// (test _test.go files are not linked into importer test binaries).
package codelens

import "github.com/snyk/snyk-ls/internal/types"

func init() {
	types.DefaultOpenBrowserFunc = func(url string) {}
}
