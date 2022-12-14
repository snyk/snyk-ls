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

package testutil

import (
	"os"
	"testing"
)

func CreateTempFile(tempDir string, t *testing.T) *os.File {
	file, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Fatal(t, "Couldn't create temp file")
	}

	t.Cleanup(func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	})
	return file
}
