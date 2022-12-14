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

package code

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getSize(t *testing.T) {
	t.Run("returns overhead", func(t *testing.T) {
		bundle := NewUploadBatch()
		bundle.documents = map[string]BundleFile{
			"uri": {},
		}

		size := bundle.getSize()

		assert.Equal(t, 12, size)
	})

	t.Run("when empty bundle should return 0", func(t *testing.T) {
		bundle := NewUploadBatch()

		size := bundle.getSize()

		assert.Equal(t, 0, size)
	})
}
