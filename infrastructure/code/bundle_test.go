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

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/notification"
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

func Test_AutofixMessages(t *testing.T) {
	fakeSnykCode := FakeSnykCodeClient{}
	mockNotifier := notification.NewMockNotifier()
	bundle := Bundle{
		SnykCode:     &fakeSnykCode,
		notifier:     mockNotifier,
		instrumentor: performance.NewTestInstrumentor(),
	}

	t.Run("Shows attempt message when fix requested", func(t *testing.T) {
		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		assert.Contains(t, mockNotifier.SentMessages(), sglsp.ShowMessageParams{
			Type:    sglsp.Info,
			Message: "Attempting to fix SNYK-123 (Snyk)",
		})
	})

	t.Run("Shows success message when fix provided", func(t *testing.T) {
		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		successMsgRequest := mockNotifier.SentMessages()[1].(snyk.ShowMessageRequest)
		assert.Equal(t, snyk.Info, successMsgRequest.Type)
		assert.Equal(t, "Congratulations! 🎉 You’ve just fixed this SNYK-123 issue. Was this fix helpful?", successMsgRequest.Message)

		// Compare button action commands
		actionCommandMap := data_structure.NewOrderedMap[snyk.MessageAction, snyk.Command]()
		commandData1 := snyk.CommandData{
			Title:     snyk.CodeSubmitFixFeedback,
			CommandId: snyk.CodeSubmitFixFeedback,
			Arguments: []any{"123e4567-e89b-12d3-a456-426614174000/1", true},
		}
		commandData2 := snyk.CommandData{
			Title:     snyk.CodeSubmitFixFeedback,
			CommandId: snyk.CodeSubmitFixFeedback,
			Arguments: []any{"123e4567-e89b-12d3-a456-426614174000/1", false},
		}
		cmd1, _ := command.CreateFromCommandData(commandData1, nil, nil, nil, nil, nil, nil)
		cmd2, _ := command.CreateFromCommandData(commandData2, nil, nil, nil, nil, nil, nil)
		positiveFeedback := snyk.MessageAction("👍")
		negativeFeedback := snyk.MessageAction("👎")
		actionCommandMap.Add(positiveFeedback, cmd1)
		actionCommandMap.Add(negativeFeedback, cmd2)

		assert.Equal(t, actionCommandMap.Keys(), successMsgRequest.Actions.Keys())

		buttonAction1, _ := successMsgRequest.Actions.Get(positiveFeedback)
		buttonAction2, _ := successMsgRequest.Actions.Get(negativeFeedback)
		assert.Equal(t, cmd1.Command(), buttonAction1.Command())
		assert.Equal(t, cmd2.Command(), buttonAction2.Command())
	})

	t.Run("Shows error message when no fix available", func(t *testing.T) {
		fakeSnykCode.NoFixSuggestions = true

		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		assert.Contains(t, mockNotifier.SentMessages(), sglsp.ShowMessageParams{
			Type:    sglsp.MTError,
			Message: "Oh snap! 😔 The fix did not remediate the issue and was not applied.",
		})
	})
}
