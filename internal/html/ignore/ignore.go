/*
 * © 2024-2026 Snyk Limited
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

// Package ignore contains the code for rendering the ignore details in the description panel.
package ignore

import (
	_ "embed"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	"github.com/snyk/go-application-framework/pkg/utils/git"

	"github.com/snyk/snyk-ls/internal/types"
)

// CreateIgnoreUnavailableReason is shown when ignore creation requires a Git remote
// that cannot be resolved for the issue's content root.
const CreateIgnoreUnavailableReason = "Cannot submit ignore: could not determine the repository URL for this folder. Please ensure the folder is part of a Git repository with a configured remote."

// remoteRepoUrlFlag is the CLI-style flag name for ignore_workflow.RemoteRepoUrlKey
// ("remote-repo-url"), as it would appear in a folder's Additional Parameters setting.
const remoteRepoUrlFlag = "--" + ignore_workflow.RemoteRepoUrlKey

// CanCreateIgnore reports whether an ignore-approval request can be submitted for
// content at contentRoot. Uses the same resolver as submitIgnoreRequest validation:
// either a Git remote must resolve for contentRoot, or a --remote-repo-url override
// must be configured for it.
func CanCreateIgnore(contentRoot string, configResolver types.ConfigResolverInterface) bool {
	if contentRoot == "" {
		return false
	}
	if _, err := git.RepoUrlFromDir(contentRoot); err == nil {
		return true
	}
	return RemoteRepoUrlOverride(configResolver, types.FilePath(contentRoot)) != ""
}

// RemoteRepoUrlOverride returns the --remote-repo-url value configured for contentRoot's
// Additional Parameters setting, or "" if none is set. This mirrors the CLI workaround for
// non-Git projects (e.g. Endevor/COBOL): --remote-repo-url lets Snyk compute a consistent
// asset ID without requiring a real Git remote, so the IDE honors the same override here
// instead of hard-blocking the ignore request.
func RemoteRepoUrlOverride(configResolver types.ConfigResolverInterface, contentRoot types.FilePath) string {
	if configResolver == nil {
		return ""
	}
	folderConfig := &types.FolderConfig{FolderPath: contentRoot, ConfigResolver: configResolver}
	params := configResolver.GetStringSlice(types.SettingAdditionalParameters, folderConfig)
	return extractFlagValue(params, remoteRepoUrlFlag)
}

// extractFlagValue returns the value of a CLI-style flag from args, supporting both the
// "--flag=value" and "--flag value" forms. Returns "" if the flag is not present.
func extractFlagValue(args []string, flag string) string {
	for i, arg := range args {
		if value, ok := strings.CutPrefix(arg, flag+"="); ok {
			return value
		}
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

//go:embed ignore_styles.css
var ignoreStyles string

//go:embed ignore_scripts.js
var ignoreScripts string

//go:embed ignore_templates.html
var ignoreTemplates string

func Styles() string {
	return ignoreStyles
}

func Scripts() string {
	return ignoreScripts
}

// AddTemplates parses the shared ignore sub-templates into the given template tree.
func AddTemplates(t *template.Template) (*template.Template, error) {
	return t.Parse(ignoreTemplates)
}

type Detail struct {
	Label string
	Value string
}

func PrepareDetailsRow(ignoreDetails *types.IgnoreDetails) []Detail {
	return []Detail{
		{"Ignore Type", ParseCategory(ignoreDetails.Category)},
		{"Expiration", FormatExpirationDate(ignoreDetails.Expiration)},
		{"Request date", FormatDate(ignoreDetails.IgnoredOn)},
		{"Requested by", ignoreDetails.IgnoredBy},
		{"Ignore reason", ignoreDetails.Reason},
		{"Request ID", ignoreDetails.IgnoreId},
		{"Status", ParseStatus(ignoreDetails.Status)},
	}
}

func ParseCategory(category string) string {
	categoryMap := map[string]string{
		"not-vulnerable":   "Not vulnerable",
		"temporary-ignore": "Ignored temporarily",
		"wont-fix":         "Won't Fix",
	}

	if result, ok := categoryMap[category]; ok {
		return result
	}
	return category
}

func ParseStatus(status testapi.SuppressionStatus) string {
	statusMap := map[testapi.SuppressionStatus]string{
		testapi.SuppressionStatusPendingIgnoreApproval: "Pending",
		testapi.SuppressionStatusIgnored:               "Approved",
	}

	if result, ok := statusMap[status]; ok {
		return result
	}
	return string(status)
}

func FormatExpirationDate(expiration string) string {
	if expiration == "" {
		return "No expiration"
	}
	parsedDate, err := time.Parse(time.RFC3339, expiration)
	if err != nil {
		return expiration
	}

	daysRemaining := int(time.Until(parsedDate).Hours() / 24)

	if daysRemaining < 0 {
		return "Expired"
	} else if daysRemaining == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", daysRemaining)
}

func FormatDate(date time.Time) string {
	month := date.Format("January")
	return fmt.Sprintf("%s %d, %d", month, date.Day(), date.Year())
}
