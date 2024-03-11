/*
 * © 2022-2024 Snyk Limited
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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

var bundleWithFiles = &UploadBatch{
	hash:      "bundleWithFilesHash",
	documents: map[string]BundleFile{"file": {}},
}
var bundleWithMultipleFiles = &UploadBatch{
	hash: "bundleWithMultipleFilesHash",
	documents: map[string]BundleFile{
		"file":    {},
		"another": {},
	},
}

func Test_BundleGroup_AddBundle(t *testing.T) {
	t.Run("when no documents - creates nothing", func(t *testing.T) {
		fakeSnykCode := FakeSnykCodeClient{}
		bundle := Bundle{
			SnykCode: &fakeSnykCode,
		}

		emptyBundle := &UploadBatch{}
		_ = bundle.Upload(context.Background(), emptyBundle)

		assert.False(t, fakeSnykCode.HasCreatedNewBundle)
		assert.False(t, fakeSnykCode.HasExtendedBundle)
	})

	t.Run("when no bundles - creates new bundle and sets hash", func(t *testing.T) {
		t.Skip("needs to be moved")
		fakeSnykCode := FakeSnykCodeClient{}
		bundle := Bundle{
			SnykCode: &fakeSnykCode,
		}

		_ = bundle.Upload(context.Background(), bundleWithFiles)

		assert.False(t, fakeSnykCode.HasExtendedBundle)
	})

	t.Run("when existing bundles - extends bundle and updates hash", func(t *testing.T) {
		fakeSnykCode := FakeSnykCodeClient{}
		bundle := Bundle{
			SnykCode: &fakeSnykCode,
		}

		_ = bundle.Upload(context.Background(), bundleWithFiles)
		oldHash := bundle.BundleHash
		_ = bundle.Upload(context.Background(), bundleWithMultipleFiles)
		newHash := bundle.BundleHash

		assert.True(t, fakeSnykCode.HasExtendedBundle)
		assert.Equal(t, 2, fakeSnykCode.TotalBundleCount)
		assert.Equal(t, 2, fakeSnykCode.ExtendedBundleCount)
		assert.NotEqual(t, oldHash, newHash)
	})
}
