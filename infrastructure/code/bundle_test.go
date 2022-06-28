package code

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/util"
)

func Test_getShardKey(t *testing.T) {
	b := Bundle{BundleHash: ""}
	const testToken = "TEST"
	t.Run("should return root path hash", func(t *testing.T) {
		// Case 1: rootPath exists
		sampleRootPath := "C:\\GIT\\root"
		// deepcode ignore HardcodedPassword/test: false positive
		token := testToken
		assert.Equal(t, util.Hash([]byte(sampleRootPath)), b.getShardKey(sampleRootPath, token))
	})

	t.Run("should return token hash", func(t *testing.T) {
		// Case 2: rootPath empty, token exists
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := testToken
		assert.Equal(t, util.Hash([]byte(token)), b.getShardKey(sampleRootPath, token))
	})

	t.Run("should return empty shard key", func(t *testing.T) {
		// Case 3: No token, no rootPath set
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := ""
		assert.Equal(t, "", b.getShardKey(sampleRootPath, token))
	})

	t.Run("should return hashed bundleHash as shard key", func(t *testing.T) {
		b.BundleHash = "Hashy Mc Hashface"
		// Case 4: bundleHash is existent, we can hash & use it. Hashing, as the bundle hash is PII
		sampleRootPath := "C:\\git"
		// deepcode ignore HardcodedPassword/test: false positive
		token := testToken
		assert.Equal(t, util.Hash([]byte(b.BundleHash)), b.getShardKey(sampleRootPath, token))
	})
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
