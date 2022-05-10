package code

import (
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/util"
)

func Test_getShardKey(t *testing.T) {
	t.Run("should return root path hash", func(t *testing.T) {
		// Case 1: rootPath exists
		sampleRootPath := "C:\\GIT\\root"
		// deepcode ignore HardcodedPassword/test: false positive
		token := "TEST"
		assert.Equal(t, util.Hash([]byte(sampleRootPath)), getShardKey(sampleRootPath, token))
	})

	t.Run("should return token hash", func(t *testing.T) {
		// Case 2: rootPath empty, token exists
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := "TEST"
		assert.Equal(t, util.Hash([]byte(token)), getShardKey(sampleRootPath, token))
	})

	t.Run("should return empty shard key", func(t *testing.T) {
		// Case 3: No token, no rootPath set
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := ""
		assert.Equal(t, "", getShardKey(sampleRootPath, token))
	})
}

func Test_BundleGroup_AddBundle(t *testing.T) {
	t.Run("when no documents - creates nothing", func(t *testing.T) {
		fakeSnykCode := FakeSnykCodeClient{}
		bundle := Bundle{
			SnykCode: &fakeSnykCode,
		}

		emptyBundle := &UploadBatch{}
		_ = bundle.Upload(emptyBundle)

		assert.False(t, fakeSnykCode.HasCreatedNewBundle)
		assert.False(t, fakeSnykCode.HasExtendedBundle)
	})

	t.Run("when no bundles - creates new bundle and sets hash", func(t *testing.T) {
		fakeSnykCode := FakeSnykCodeClient{}
		bundle := Bundle{
			SnykCode: &fakeSnykCode,
		}

		_ = bundle.Upload(bundleWithFiles)

		assert.True(t, fakeSnykCode.HasCreatedNewBundle)
		assert.False(t, fakeSnykCode.HasExtendedBundle)
		assert.NotEmpty(t, bundle.BundleHash)
	})

	t.Run("when existing bundles - extends bundle and updates hash", func(t *testing.T) {
		fakeSnykCode := FakeSnykCodeClient{}
		bundle := Bundle{
			SnykCode: &fakeSnykCode,
		}

		_ = bundle.Upload(bundleWithFiles)
		oldHash := bundle.BundleHash
		_ = bundle.Upload(bundleWithMultipleFiles)
		newHash := bundle.BundleHash

		assert.True(t, fakeSnykCode.HasExtendedBundle)
		assert.Equal(t, fakeSnykCode.TotalBundleCount, 2)
		assert.Equal(t, fakeSnykCode.ExtendedBundleCount, 1)
		assert.NotEqual(t, oldHash, newHash)
	})
}

var bundleWithFiles = &UploadBatch{
	hash:      "bundleWithFilesHash",
	documents: map[lsp.DocumentURI]BundleFile{lsp.DocumentURI("file"): {}},
}
var bundleWithMultipleFiles = &UploadBatch{
	hash: "bundleWithMultipleFilesHash",
	documents: map[lsp.DocumentURI]BundleFile{
		lsp.DocumentURI("file"):    {},
		lsp.DocumentURI("another"): {},
	},
}
