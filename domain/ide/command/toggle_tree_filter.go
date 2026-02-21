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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// toggleTreeFilter handles the snyk.toggleTreeFilter command. It updates the
// severity filter or issue view options in config, then triggers a config change
// which re-emits the tree view via $/snyk.treeView notification.
type toggleTreeFilter struct {
	command types.CommandData
	c       *config.Config
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
	if ws := cmd.c.Workspace(); ws != nil {
		go ws.HandleConfigChange()
	}

	return nil, nil
}

func (cmd *toggleTreeFilter) applySeverityFilter(value string, enabled bool) error {
	current := cmd.c.FilterSeverity()
	switch value {
	case "critical":
		current.Critical = enabled
	case "high":
		current.High = enabled
	case "medium":
		current.Medium = enabled
	case "low":
		current.Low = enabled
	default:
		return fmt.Errorf("unknown severity value %q", value)
	}
	cmd.c.SetSeverityFilter(util.Ptr(current))
	return nil
}

func (cmd *toggleTreeFilter) applyIssueViewFilter(value string, enabled bool) error {
	current := cmd.c.IssueViewOptions()
	switch value {
	case "openIssues":
		current.OpenIssues = enabled
	case "ignoredIssues":
		current.IgnoredIssues = enabled
	default:
		return fmt.Errorf("unknown issue view value %q", value)
	}
	cmd.c.SetIssueViewOptions(util.Ptr(current))
	return nil
}
