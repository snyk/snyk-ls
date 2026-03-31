/*
 * © 2026 Snyk Limited All rights reserved.
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

package directory_check

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Style definitions for colored output
var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")) // Green
	warningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("3")) // Yellow
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("1")) // Red
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("4")) // Blue
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("8")) // Gray
)

// FormatResultsText formats the diagnostics result as human-readable text
// If useColor is true, ANSI color codes will be included in the output
func FormatResultsText(result *DiagnosticsResult, useColor bool) string {
	if useColor {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	var sb strings.Builder

	// Title
	sb.WriteString(renderTitle("IDE Directory Diagnostics", useColor))
	sb.WriteString("\n\n")

	// Current user section
	sb.WriteString(renderTitle("Current User Information", useColor))
	sb.WriteString("\n")
	if result.CurrentUser != "" {
		sb.WriteString(renderStyled(fmt.Sprintf("Username: %s", result.CurrentUser), infoStyle, useColor))
	} else {
		sb.WriteString(renderStyled("⚠ Unable to determine current username", warningStyle, useColor))
	}
	sb.WriteString("\n\n")

	// Directory results section
	sb.WriteString(renderTitle("Potential Snyk Used Configuration and CLI Download Directories", useColor))
	sb.WriteString("\n")

	if len(result.DirectoryResults) == 0 {
		sb.WriteString(renderStyled("No directories checked", dimStyle, useColor))
		sb.WriteString("\n")
	} else {
		for _, dirResult := range result.DirectoryResults {
			sb.WriteString(formatDirectoryResult(dirResult, useColor))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// FormatResultsJSON formats the diagnostics result as JSON
func FormatResultsJSON(result *DiagnosticsResult) (string, error) {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal diagnostics result to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

// formatDirectoryResult formats a single directory check result
func formatDirectoryResult(result DirectoryCheckResult, useColor bool) string {
	var sb strings.Builder

	// Show the wanted path first
	sb.WriteString(renderStyled(
		fmt.Sprintf("Directory: %s (Purpose: %s)", result.PathWanted, result.Purpose),
		infoStyle, useColor))
	sb.WriteString("\n")

	// Handle errors
	if result.Error != "" {
		sb.WriteString(renderStyled(fmt.Sprintf("  ✗ Error: %s", result.Error), errorStyle, useColor))
		sb.WriteString("\n")
		return sb.String()
	}

	// Check if the wanted path exists or if we found a parent
	if result.PathWanted == result.PathFound {
		// Directory exists
		sb.WriteString(renderStyled("  ✓ Exists", successStyle, useColor))
		sb.WriteString("\n")
	} else {
		// Directory doesn't exist, showing parent
		sb.WriteString(renderStyled("  ⚠ Does not exist", warningStyle, useColor))
		sb.WriteString("\n")
		sb.WriteString(renderStyled(fmt.Sprintf("  Nearest existing parent: %s", result.PathFound), dimStyle, useColor))
		sb.WriteString("\n")
	}

	// Show write permissions
	if result.IsWritable {
		sb.WriteString(renderStyled(fmt.Sprintf("  ✓ Writable (permissions: %s)", result.Permissions), successStyle, useColor))
		sb.WriteString("\n")
	} else {
		sb.WriteString(renderStyled(fmt.Sprintf("  ✗ Not writable (permissions: %s)", result.Permissions), errorStyle, useColor))
		sb.WriteString("\n")
	}

	// Show binaries found (only if the wanted path exists and may contain a Snyk CLI binary)
	if result.PathWanted == result.PathFound && result.MayContainCLI {
		if len(result.BinariesFound) > 0 {
			sb.WriteString(renderStyled(
				fmt.Sprintf("  Found %d potential Snyk CLI binary/binaries:", len(result.BinariesFound)),
				successStyle, useColor))
			sb.WriteString("\n")
			for _, binary := range result.BinariesFound {
				sb.WriteString(renderStyled(
					fmt.Sprintf("    • %s (permissions: %s)", binary.Name, binary.Permissions),
					successStyle, useColor))
				sb.WriteString("\n")
			}
		} else {
			sb.WriteString(renderStyled("  No Snyk CLI binaries found", dimStyle, useColor))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// renderTitle renders a section title
func renderTitle(title string, useColor bool) string {
	divider := strings.Repeat("─", len(title)+4)
	if useColor {
		return fmt.Sprintf("%s\n  %s\n%s",
			infoStyle.Render(divider),
			infoStyle.Bold(true).Render(title),
			infoStyle.Render(divider))
	}
	return fmt.Sprintf("%s\n  %s\n%s", divider, title, divider)
}

// renderStyled applies a style if color is enabled, otherwise returns plain text
func renderStyled(text string, style lipgloss.Style, useColor bool) string {
	if useColor {
		return style.Render(text)
	}
	return text
}
