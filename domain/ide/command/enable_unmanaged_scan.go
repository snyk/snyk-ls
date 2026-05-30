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

package command

import (
	"context"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/types"
)

// enableUnmanagedScan is the command bound to the "Yes" action of the C/C++
// auto-detect prompt. It persists snyk_oss_unmanaged_enabled = true for the
// given folder so subsequent OSS scans append --unmanaged.
type enableUnmanagedScan struct {
	command types.CommandData
	engine  workflow.Engine
}

func (cmd *enableUnmanagedScan) Command() types.CommandData {
	return cmd.command
}

func (cmd *enableUnmanagedScan) Execute(_ context.Context) (any, error) {
	if len(cmd.command.Arguments) < 1 {
		return nil, fmt.Errorf("enableUnmanagedScan: missing folderPath argument")
	}
	folderPath, ok := cmd.command.Arguments[0].(string)
	if !ok || folderPath == "" {
		return nil, fmt.Errorf("enableUnmanagedScan: folderPath must be a non-empty string")
	}

	conf := cmd.engine.GetConfiguration()
	types.SetFolderUserSetting(conf, types.FilePath(folderPath), types.SettingSnykOssUnmanagedEnabled, true)
	return true, nil
}
