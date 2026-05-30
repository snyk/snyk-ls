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
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/data_structure"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	unmanagedPromptMessage = "Snyk detected C/C++ files in this project. Snyk Open Source can scan unmanaged C/C++ projects (passing --unmanaged to the CLI). Enable unmanaged scanning for this folder?"
	unmanagedPromptYes     = "Yes, enable unmanaged scan"
	unmanagedPromptNo      = "No, thanks"
)

// detectFunc is replaceable in tests.
type detectFunc func(string) bool

// maybePromptForUnmanagedScan, if the folder hasn't already been prompted and
// the folder looks like a C/C++ project, marks the folder as prompted and
// sends a window/showMessageRequest with Yes/No actions. The "Yes" action
// invokes EnableUnmanagedScanCommand which persists
// snyk_oss_unmanaged_enabled = true.
//
// Returns true if a prompt was sent. The prompted flag is persisted before
// sending so a crash mid-prompt does not cause re-prompts.
func maybePromptForUnmanagedScan(
	notifier noti.Notifier,
	conf configuration.Configuration,
	resolver types.ConfigResolverInterface,
	folder *types.FolderConfig,
	detect detectFunc,
) bool {
	if notifier == nil || conf == nil || resolver == nil || folder == nil {
		return false
	}
	if resolver.GetBool(types.SettingSnykOssUnmanagedEnabled, folder) {
		return false
	}
	if resolver.GetBool(types.SettingSnykOssUnmanagedPrompted, folder) {
		return false
	}
	if detect == nil {
		detect = HasCPPArtefacts
	}
	if !detect(string(folder.FolderPath)) {
		return false
	}

	// Persist before sending so a missed callback / crash does not re-prompt.
	types.SetFolderUserSetting(conf, folder.FolderPath, types.SettingSnykOssUnmanagedPrompted, true)

	actions := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()
	yes := types.CommandData{
		Title:     unmanagedPromptYes,
		CommandId: types.EnableUnmanagedScanCommand,
		Arguments: []any{string(folder.FolderPath)},
	}
	actions.Add(types.MessageAction(unmanagedPromptYes), yes)
	actions.Add(types.MessageAction(unmanagedPromptNo), types.CommandData{Title: unmanagedPromptNo})

	notifier.Send(types.ShowMessageRequest{
		Message: unmanagedPromptMessage,
		Type:    types.Info,
		Actions: actions,
	})
	return true
}
