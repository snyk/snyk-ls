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
	"time"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/internal/types"
)

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
