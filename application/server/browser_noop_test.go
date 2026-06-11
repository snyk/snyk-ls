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

// Package server — test-only init for DefaultOpenBrowserFunc.
// Mirrors application/di/browser_noop_test.go: both files are _test.go files
// compiled only into their respective package's test binaries. Without this,
// server package tests that import application/di as a production dependency
// would not benefit from the di package's own browser_noop_test.go init().
package server

import "github.com/snyk/snyk-ls/internal/types"

func init() {
	types.DefaultOpenBrowserFunc = func(url string) {}
}
