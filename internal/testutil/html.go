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

package testutil

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// SelectOption describes a rendered HTML select option.
type SelectOption struct {
	Value    string
	Text     string
	Selected bool
}

// RequireOpeningTagByName returns the named opening tag or fails the test.
func RequireOpeningTagByName(t *testing.T, html, tag, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`<` + tag + `\b[^>]*\bname="` + regexp.QuoteMeta(name) + `"[^>]*>`)
	match := pattern.FindString(html)
	require.NotEmpty(t, match, "%s[name=%q] must be present", tag, name)
	return match
}

// RequireElementByName returns the complete named element or fails the test.
func RequireElementByName(t *testing.T, html, tag, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`(?s)<` + tag + `\b[^>]*\bname="` + regexp.QuoteMeta(name) + `"[^>]*>.*?</` + tag + `>`)
	match := pattern.FindString(html)
	require.NotEmpty(t, match, "%s[name=%q] must be present", tag, name)
	return match
}

// ParseSelectOptions extracts ordered options from select element markup.
func ParseSelectOptions(t *testing.T, selectMarkup string) []SelectOption {
	t.Helper()
	optionPattern := regexp.MustCompile(`(?s)<option\b[^>]*\bvalue="([^"]*)"([^>]*)>([^<]*)</option>`)
	matches := optionPattern.FindAllStringSubmatch(selectMarkup, -1)
	require.NotEmpty(t, matches, "select must contain options")

	options := make([]SelectOption, 0, len(matches))
	for _, match := range matches {
		options = append(options, SelectOption{
			Value:    match[1],
			Text:     strings.TrimSpace(match[3]),
			Selected: strings.Contains(match[2], "selected"),
		})
	}
	return options
}
