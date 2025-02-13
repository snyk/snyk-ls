/*
 * © 2022 Snyk Limited All rights reserved.
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

package util

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func Test_hash(t *testing.T) {
	assert.Equal(t,
		"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		Hash([]byte("hello\n")),
	)
}

func Test_hashLatin1File(t *testing.T) {
	dir, _ := os.Getwd()
	content, _ := os.ReadFile(filepath.Join(dir, "testdata", "pom.xml"))
	assert.Equal(t, "ec5f2dbc5f65d7cae9c96046681dc6731ab995dd8021f7fdd63cff5432f74608", Hash(content))
}

func Test_hashExploit(t *testing.T) {
	dir, _ := os.Getwd()
	content, _ := os.ReadFile(filepath.Join(dir, "testdata", "rshell_font.php"))
	assert.False(t, utf8.Valid(content))
	assert.Equal(t, "d1492cb636898802bb3fae73be0fed97629fcfd918ceddc1c63a6f4a5cbc74d4", Hash(content))
}
