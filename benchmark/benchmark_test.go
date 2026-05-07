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

package benchmark

import (
	"io/fs"
	"os"
	"runtime"
	"testing"
)

func benchFixtureScale() (codeDirs, ossDirs int) {
	if os.Getenv("BENCHMARK_FULL_FIXTURE") == "1" {
		return CodeFolderCount, OSSFolderCount
	}
	return 20, 20
}

func BenchmarkGenerateMonorepoFixture(b *testing.B) {
	codeDirs, ossDirs := benchFixtureScale()
	b.ReportAllocs()
	for b.Loop() {
		root := b.TempDir()
		if err := generateMonorepoFixture(b, root, codeDirs, ossDirs); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMonorepoWalk(b *testing.B) {
	root := b.TempDir()
	codeDirs, ossDirs := benchFixtureScale()
	if err := generateMonorepoFixture(b, root, codeDirs, ossDirs); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var n int
		if err := WalkMonorepoFixture(root, func(_ string, _ fs.DirEntry) error {
			n++
			return nil
		}); err != nil {
			b.Fatal(err)
		}
		runtime.KeepAlive(n)
	}
}
