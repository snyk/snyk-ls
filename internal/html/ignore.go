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

package html

import (
	"fmt"
	"time"

	codeClientSarif "github.com/snyk/code-client-go/sarif"

	"github.com/snyk/snyk-ls/internal/types"
)

type IgnoreDetail struct {
	Label string
	Value string
}

func PrepareIgnoreDetailsRow(ignoreDetails *types.IgnoreDetails) []IgnoreDetail {
	return []IgnoreDetail{
		{"Category", ParseCategory(ignoreDetails.Category)},
		{"Expiration", FormatExpirationDate(ignoreDetails.Expiration)},
		{"Ignored On", FormatDate(ignoreDetails.IgnoredOn)},
		{"Ignored By", ignoreDetails.IgnoredBy},
		{"Reason", ignoreDetails.Reason},
		{"Status", ParseStatus(ignoreDetails.Status)},
	}
}

func ParseCategory(category string) string {
	categoryMap := map[string]string{
		"not-vulnerable":   "Not vulnerable",
		"temporary-ignore": "Ignored temporarily",
		"wont-fix":         "Ignored permanently",
	}

	if result, ok := categoryMap[category]; ok {
		return result
	}
	return category
}

func ParseStatus(status codeClientSarif.SuppresionStatus) string {
	statusMap := map[codeClientSarif.SuppresionStatus]string{
		codeClientSarif.UnderReview: "Pending",
		codeClientSarif.Accepted:    "Approved",
		codeClientSarif.Rejected:    "Rejected",
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
