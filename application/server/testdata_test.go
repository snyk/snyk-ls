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

package server

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSmokeFixtureFilesExist(t *testing.T) {
	fixtures := []string{
		"testdata/smokefix/code/vuln.js",
		"testdata/smokefix/oss/package.json",
		"testdata/smokefix/oss/package-lock.json",
		"testdata/smokefix/iac/main.tf",
		"testdata/smokefix/java/VulnApp.java",
	}
	for _, f := range fixtures {
		info, err := os.Stat(f)
		assert.NoErrorf(t, err, "%s should exist", f)
		if err == nil {
			assert.Greaterf(t, info.Size(), int64(0), "%s should be non-empty", f)
		}
	}
}
