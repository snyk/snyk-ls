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

package oss

import (
	"os"
	"testing"
)

func BenchmarkUnmarshallOssJson(b *testing.B) {
	fixture, err := os.ReadFile("testdata/oss-result.json")
	if err != nil {
		b.Fatalf("failed to read fixture: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, benchErr := UnmarshallOssJson(fixture)
		if benchErr != nil || len(results) == 0 {
			b.Fatalf("unexpected result: err=%v, len=%d", benchErr, len(results))
		}
	}
}
