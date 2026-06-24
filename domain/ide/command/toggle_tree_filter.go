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
	"math"

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
	if len(args) < 1 {
		return nil, fmt.Errorf("expected at least 1 argument [filterType], got %d", len(args))
	}

	filterType, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("filterType must be a string")
	}

	// Each filter type validates only the arguments it uses: severity/issueView
	// take [filterType, filterValue, enabled]; riskScore takes a numeric threshold
	// in args[2]; reset takes no further arguments.
	switch filterType {
	case "severity":
		filterValue, enabled, err := toggleArgs(args)
		if err != nil {
			return nil, err
		}
		if err := cmd.applySeverityFilter(filterValue, enabled); err != nil {
			return nil, err
		}
	case "issueView":
		filterValue, enabled, err := toggleArgs(args)
		if err != nil {
			return nil, err
		}
		if err := cmd.applyIssueViewFilter(filterValue, enabled); err != nil {
			return nil, err
		}
	case "riskScore":
		if len(args) < 3 {
			return nil, fmt.Errorf("expected 3 arguments [filterType, filterValue, threshold], got %d", len(args))
		}
		threshold, err := toInt(args[2])
		if err != nil {
			return nil, fmt.Errorf("risk score threshold must be a number: %w", err)
		}
		cmd.applyRiskScoreFilter(threshold)
	case "reset":
		// The popover's Reset button restores all of its filters at once and needs
		// no further arguments. Batched into one command so the whole reset triggers
		// a single config-change cycle / tree re-render (see applyResetFilters).
		cmd.applyResetFilters()
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

// applyRiskScoreFilter writes the risk-score threshold to every open folder. Like
// the severity/issue-view toggles, the slider is workspace-wide: changing it
// aligns all folders (resolving a "mixed" state). The threshold is clamped to the
// valid [0,1000] domain (the same range the slider and isVisibleRiskScore use):
// the slider can't produce out-of-range values, but this command is a public LSP
// entry point, so normalising here keeps every folder in a representable state.
func (cmd *toggleTreeFilter) applyRiskScoreFilter(threshold int) {
	if threshold < 0 {
		threshold = 0
	} else if threshold > 1000 {
		threshold = 1000
	}
	cmd.writeFilterToAllFolders(types.SettingRiskScoreThreshold, threshold)
}

// applyResetFilters restores the popover's filters — risk score and the two
// issue-view options — to their defaults across every open folder. Severity
// filters are not part of the popover and are intentionally left untouched. All
// writes happen before Execute's single HandleConfigChange/notify, so one reset
// click costs one config-change cycle rather than one per control.
//
// Writes go to ALL open folders, not just flag-enabled ones, matching the
// severity/issue-view toggles: the toolbar is workspace-wide, so a reset aligns
// every folder. A write to a folder whose gating flag (UseOsTestWorkflow /
// SnykCodeConsistentIgnores) is off is inert — the per-folder server filter is
// gated by the same flag (see folder.buildFilterContext) — so resetting it to the
// default changes nothing for that folder. The issue-view pair goes through
// types.SetIssueViewOptionsForFolder so this write site can't drift from the
// canonical one.
func (cmd *toggleTreeFilter) applyResetFilters() {
	conf := cmd.engine.GetConfiguration()
	defaults := types.DefaultIssueViewOptions()
	for _, f := range cmd.workspaceFolders() {
		types.SetUserFolder(conf, f.Path(), types.SettingRiskScoreThreshold, 0)
		types.SetIssueViewOptionsForFolder(conf, f.Path(), &defaults)
	}
}

// writeFilterToAllFolders writes a single folder-scoped filter setting to every
// open folder, leaving each folder's OTHER filter values untouched. The toolbar
// is workspace-wide, so a change applies the toggled value to all folders
// (e.g. clicking a "mixed" button enables just that severity everywhere) — it
// must not rewrite the other filters, which can legitimately differ per folder.
// Writing per-folder only (not user-global) also keeps the toggle from moving the
// global default in lockstep; the per-folder value is authoritative for filtering,
// outranking LDX-Sync remote defaults.
//
// Risk-score and issue-view writes land on every open folder including ones whose
// gating flag is off; that is inert, since the per-folder server filter is gated by
// the same flag (see folder.buildFilterContext).
func (cmd *toggleTreeFilter) writeFilterToAllFolders(settingName string, value any) {
	conf := cmd.engine.GetConfiguration()
	for _, f := range cmd.workspaceFolders() {
		types.SetUserFolder(conf, f.Path(), settingName, value)
	}
}

// toggleArgs extracts the [filterValue, enabled] pair shared by the severity and
// issueView toggles, which both require all three command arguments.
func toggleArgs(args []any) (string, bool, error) {
	if len(args) < 3 {
		return "", false, fmt.Errorf("expected 3 arguments [filterType, filterValue, enabled], got %d", len(args))
	}
	filterValue, ok := args[1].(string)
	if !ok {
		return "", false, fmt.Errorf("filterValue must be a string")
	}
	enabled, ok := args[2].(bool)
	if !ok {
		return "", false, fmt.Errorf("enabled must be a bool")
	}
	return filterValue, enabled, nil
}

// toInt coerces a command argument to an int. JSON numbers arrive as float64 over
// the LSP boundary, but int/int64 are accepted too for direct in-process callers
// and tests. Non-finite floats (NaN/Inf) are rejected: int(NaN) is
// implementation-defined in Go and the downstream [0,1000] clamp only bounds
// range, so they are caught here at the public LSP boundary.
func toInt(v any) (int, error) {
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, fmt.Errorf("non-finite number %v", n)
		}
		return int(n), nil
	case int:
		return n, nil
	case int64:
		return int(n), nil
	default:
		return 0, fmt.Errorf("unsupported numeric type %T", v)
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
