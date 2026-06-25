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

	"github.com/snyk/snyk-ls/application/config"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

// toggleTreeFilter handles the snyk.toggleTreeFilter command. It updates the
// severity filter or issue view options in config, then triggers a config change
// which re-emits the tree view via $/snyk.treeView notification, and emits a
// $/snyk.configuration notification so an open settings window reflects the new
// filter values.
type toggleTreeFilter struct {
	command        types.CommandData
	engine         workflow.Engine
	notifier       noti.Notifier
	configResolver types.ConfigResolverInterface
}

func (cmd *toggleTreeFilter) Command() types.CommandData {
	return cmd.command
}

func (cmd *toggleTreeFilter) Execute(_ context.Context) (any, error) {
	args := cmd.command.Arguments
	if len(args) < 3 {
		return nil, fmt.Errorf("expected 3 arguments [filterType, filterValue, enabled], got %d", len(args))
	}

	filterType, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("filterType must be a string")
	}
	filterValue, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("filterValue must be a string")
	}
	enabled, ok := args[2].(bool)
	if !ok {
		return nil, fmt.Errorf("enabled must be a bool")
	}

	switch filterType {
	case "severity":
		if err := cmd.applySeverityFilter(filterValue, enabled); err != nil {
			return nil, err
		}
	case "issueView":
		if err := cmd.applyIssueViewFilter(filterValue, enabled); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown filter type %q", filterType)
	}

	// Trigger the standard config change flow: re-publish diagnostics and
	// re-emit summary + tree view via $/snyk.treeView notification.
	if ws := config.GetWorkspace(cmd.engine.GetConfiguration()); ws != nil {
		go ws.HandleConfigChange()
	}

	// Emit the current configuration so an open settings window reflects the new
	// filter values without being reopened. This is the same $/snyk.configuration
	// notification a settings change already sends back; it is a one-way state
	// push (the settings view applies it, it does not echo a change), so it does
	// not create a toggle<->settings loop.
	cmd.notifyConfigurationChanged()

	return nil, nil
}

func (cmd *toggleTreeFilter) applySeverityFilter(value string, enabled bool) error {
	var settingName string
	switch value {
	case "critical":
		settingName = types.SettingSeverityFilterCritical
	case "high":
		settingName = types.SettingSeverityFilterHigh
	case "medium":
		settingName = types.SettingSeverityFilterMedium
	case "low":
		settingName = types.SettingSeverityFilterLow
	default:
		return fmt.Errorf("unknown severity value %q", value)
	}
	cmd.writeFilterToAllFolders(settingName, enabled)
	return nil
}

func (cmd *toggleTreeFilter) applyIssueViewFilter(value string, enabled bool) error {
	var settingName string
	switch value {
	case "openIssues":
		settingName = types.SettingIssueViewOpenIssues
	case "ignoredIssues":
		settingName = types.SettingIssueViewIgnoredIssues
	default:
		return fmt.Errorf("unknown issue view value %q", value)
	}
	cmd.writeFilterToAllFolders(settingName, enabled)
	return nil
}

// writeFilterToAllFolders writes a single folder-scoped filter setting to every
// open folder, leaving each folder's OTHER filter values untouched. The toolbar
// is workspace-wide, so a toggle applies the toggled severity to all folders
// (e.g. clicking a "mixed" button enables just that severity everywhere) — it
// must not rewrite the other severities, which can legitimately differ per
// folder. Writing per-folder only (not user-global) also keeps the toggle from
// moving the global default in lockstep; the per-folder value is authoritative
// for filtering, outranking LDX-Sync remote defaults.
func (cmd *toggleTreeFilter) writeFilterToAllFolders(settingName string, enabled bool) {
	conf := cmd.engine.GetConfiguration()
	for _, f := range cmd.workspaceFolders() {
		types.SetUserFolder(conf, f.Path(), settingName, enabled)
	}
}

// workspaceFolders returns the current workspace folders (nil if no workspace).
func (cmd *toggleTreeFilter) workspaceFolders() []types.Folder {
	ws := config.GetWorkspace(cmd.engine.GetConfiguration())
	if ws == nil {
		return nil
	}
	return ws.Folders()
}

// notifyConfigurationChanged sends the current configuration to the IDE via the
// $/snyk.configuration notification so an open settings window can reflect the
// updated per-folder filter values. featureFlagService is nil here (the same as
// the settings-side sendFolderConfigUpdateIfNeeded), since only the filter
// values are relevant to this push.
func (cmd *toggleTreeFilter) notifyConfigurationChanged() {
	if cmd.notifier == nil {
		return
	}
	lspConfig := BuildLspConfiguration(cmd.engine.GetConfiguration(), cmd.engine, cmd.engine.GetLogger(), cmd.configResolver)
	cmd.notifier.Send(lspConfig)
}
