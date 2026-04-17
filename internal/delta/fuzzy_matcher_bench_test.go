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

package delta

import (
	"fmt"
	"testing"

	"github.com/snyk/snyk-ls/internal/types"
)

// BenchmarkFuzzyMatcher_Match_largeSameRule exercises matching when many base issues share one rule ID (megaproject OSS).
func BenchmarkFuzzyMatcher_Match_largeSameRule(b *testing.B) {
	const n = 5000
	base := make([]Identifiable, n)
	current := make([]Identifiable, n)
	root := types.FilePath("/tmp/wd")
	for i := range n {
		fp := fmt.Sprintf("fp-%08d", i)
		path := root + "/" + types.FilePath(fmt.Sprintf("oss_%03d/package.json", i%500))
		base[i] = &mockIdentifiable{
			ruleId:         "oss/rule",
			path:           path,
			contentRoot:    root,
			startLine:      1,
			endLine:        1,
			startColumn:    0,
			endColumn:      10,
			fingerprint:    fp,
			globalIdentity: fmt.Sprintf("id-%d", i),
		}
		// Same finding, different clone path (simulates reference vs working dir).
		curPath := types.FilePath(fmt.Sprintf("/other/root/oss_%03d/package.json", i%500))
		current[i] = &mockIdentifiable{
			ruleId:      "oss/rule",
			path:        curPath,
			contentRoot: "/other/root",
			startLine:   1,
			endLine:     1,
			startColumn: 0,
			endColumn:   10,
			fingerprint: fp,
		}
	}

	m := NewFuzzyMatcher()
	b.ResetTimer()
	for range b.N {
		_, err := m.Match(base, current)
		if err != nil {
			b.Fatal(err)
		}
	}
}
