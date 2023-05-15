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
	"context"
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/util"
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

func Test_AutofixProgress(t *testing.T) {
	setupFn := func(hasFixSuggestions bool) (Bundle, *notification.MockNotifier, chan lsp.ProgressParams) {

		fakeSnykCode := FakeSnykCodeClient{
			NoFixSuggestions: !hasFixSuggestions,
		}
		mockNotifier := notification.NewMockNotifier()
		progressChan := make(chan lsp.ProgressParams, 4)
		progressTracker := progress.NewTestTracker(progressChan, nil)

		return Bundle{
			SnykCode:     &fakeSnykCode,
			notifier:     mockNotifier,
			instrumentor: performance.NewTestInstrumentor(),
			progress:     progressTracker,
		}, mockNotifier, progressChan
	}

	t.Run("Shows attempt message when fix requested", func(t *testing.T) {
		bundle, mockNotifier, _ := setupFn(true)
		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		assert.Contains(t, mockNotifier.SentMessages(), sglsp.ShowMessageParams{
			Type:    sglsp.Info,
			Message: "Attempting to fix SNYK-123 (Snyk)",
		})
	})

	t.Run("Shows success message when fix provided", func(t *testing.T) {
		bundle, mockNotifier, _ := setupFn(true)
		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		assert.Contains(t, mockNotifier.SentMessages(), sglsp.ShowMessageParams{
			Type:    sglsp.Info,
			Message: "Congratulations! 🎉 You’ve just fixed this SNYK-123 issue.",
		})
	})

	t.Run("Shows error message when no fix available", func(t *testing.T) {
		bundle, mockNotifier, _ := setupFn(false)

		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		assert.Contains(t, mockNotifier.SentMessages(), sglsp.ShowMessageParams{
			Type:    sglsp.MTError,
			Message: "Oh snap! 😔 The fix did not remediate the issue and was not applied.",
		})
	})

	t.Run("Begins progress when fix requested", func(t *testing.T) {
		bundle, _, progressChan := setupFn(true)

		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		// Use eventually to avoid deadlocking on the progress channel
		assert.Eventually(t, func() bool {
			<-progressChan // first message is irrelevant
			beginProgressMsg := <-progressChan
			return beginProgressMsg.Value.(lsp.WorkDoneProgressBegin).Title == "Attempting to fix SNYK-123 (Snyk)"
		}, time.Second, time.Millisecond)
	})

	t.Run("Ends progress when fix is provided", func(t *testing.T) {
		bundle, _, progressChan := setupFn(true)

		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		// Use eventually to avoid deadlocking on the progress channel
		assert.Eventually(t, func() bool {
			// first two messages are begin and report progress
			<-progressChan
			<-progressChan
			endProgressMsg := <-progressChan
			return endProgressMsg.Value.(lsp.WorkDoneProgressEnd).Kind == "end"
		}, time.Second, time.Millisecond)
	})

	t.Run("Ends progress when no fix provided", func(t *testing.T) {
		bundle, _, progressChan := setupFn(false)

		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		// Use eventually to avoid deadlocking on the progress channel
		assert.Eventually(t, func() bool {
			// first two messages are begin and report progress
			<-progressChan
			<-progressChan
			endProgressMsg := <-progressChan
			return endProgressMsg.Value.(lsp.WorkDoneProgressEnd).Kind == "end"
		}, time.Second, time.Millisecond)
	})
}
