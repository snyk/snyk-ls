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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestMaybePromptForUnmanagedScan(t *testing.T) {
	const folder types.FilePath = "/repo/cpp-project"

	t.Run("prompts when detector hits and not yet prompted", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		resolver := defaultResolver(t, engine)
		notifier := notification.NewMockNotifier()
		fc := &types.FolderConfig{FolderPath: folder, ConfigResolver: resolver}

		sent := maybePromptForUnmanagedScan(notifier, engine.GetConfiguration(), resolver, fc, func(string) bool { return true })

		assert.True(t, sent, "prompt should be sent")
		msgs := notifier.SentMessages()
		require.Len(t, msgs, 1)
		req, ok := msgs[0].(types.ShowMessageRequest)
		require.True(t, ok, "should be a ShowMessageRequest")
		assert.Equal(t, types.Info, req.Type)
		require.NotNil(t, req.Actions)
		assert.Len(t, req.Actions.Keys(), 2, "Yes + No actions")
		yes, ok := req.Actions.Get(types.MessageAction(unmanagedPromptYes))
		require.True(t, ok)
		assert.Equal(t, types.EnableUnmanagedScanCommand, yes.CommandId)
		assert.Equal(t, []any{string(folder)}, yes.Arguments)
		assert.True(t, resolver.GetBool(types.SettingSnykOssUnmanagedPrompted, fc),
			"prompted flag should be set before sending")
	})

	t.Run("does not prompt when detector misses", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		resolver := defaultResolver(t, engine)
		notifier := notification.NewMockNotifier()
		fc := &types.FolderConfig{FolderPath: folder, ConfigResolver: resolver}

		sent := maybePromptForUnmanagedScan(notifier, engine.GetConfiguration(), resolver, fc, func(string) bool { return false })

		assert.False(t, sent)
		assert.Empty(t, notifier.SentMessages())
	})

	t.Run("does not prompt when already prompted", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		resolver := defaultResolver(t, engine)
		notifier := notification.NewMockNotifier()
		fc := &types.FolderConfig{FolderPath: folder, ConfigResolver: resolver}
		types.SetFolderUserSetting(engine.GetConfiguration(), folder, types.SettingSnykOssUnmanagedPrompted, true)

		sent := maybePromptForUnmanagedScan(notifier, engine.GetConfiguration(), resolver, fc, func(string) bool { return true })

		assert.False(t, sent)
		assert.Empty(t, notifier.SentMessages())
	})

	t.Run("does not prompt when already enabled", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		resolver := defaultResolver(t, engine)
		notifier := notification.NewMockNotifier()
		fc := &types.FolderConfig{FolderPath: folder, ConfigResolver: resolver}
		types.SetFolderUserSetting(engine.GetConfiguration(), folder, types.SettingSnykOssUnmanagedEnabled, true)

		sent := maybePromptForUnmanagedScan(notifier, engine.GetConfiguration(), resolver, fc, func(string) bool { return true })

		assert.False(t, sent)
		assert.Empty(t, notifier.SentMessages())
	})

	t.Run("returns false when notifier is nil", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		resolver := defaultResolver(t, engine)
		fc := &types.FolderConfig{FolderPath: folder, ConfigResolver: resolver}

		sent := maybePromptForUnmanagedScan(nil, engine.GetConfiguration(), resolver, fc, func(string) bool { return true })

		assert.False(t, sent)
	})

	t.Run("returns false when conf is nil", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		resolver := defaultResolver(t, engine)
		notifier := notification.NewMockNotifier()
		fc := &types.FolderConfig{FolderPath: folder, ConfigResolver: resolver}

		sent := maybePromptForUnmanagedScan(notifier, nil, resolver, fc, func(string) bool { return true })

		assert.False(t, sent)
		assert.Empty(t, notifier.SentMessages())
	})

	t.Run("returns false when resolver is nil", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		notifier := notification.NewMockNotifier()
		fc := &types.FolderConfig{FolderPath: folder}

		sent := maybePromptForUnmanagedScan(notifier, engine.GetConfiguration(), nil, fc, func(string) bool { return true })

		assert.False(t, sent)
		assert.Empty(t, notifier.SentMessages())
	})

	t.Run("returns false when folder is nil", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		resolver := defaultResolver(t, engine)
		notifier := notification.NewMockNotifier()

		sent := maybePromptForUnmanagedScan(notifier, engine.GetConfiguration(), resolver, nil, func(string) bool { return true })

		assert.False(t, sent)
		assert.Empty(t, notifier.SentMessages())
	})
}
