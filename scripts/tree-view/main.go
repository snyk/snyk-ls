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

// ABOUTME: Generates a standalone tree view HTML preview with example data.
// ABOUTME: The output is the exact HTML that IDEs receive via $/snyk.treeView,
// ABOUTME: with ${ideStyle}, ${ideScript}, and ${nonce} placeholders replaced
// ABOUTME: by demo values — simulating what an IDE would do before rendering.
// ABOUTME: Run with: go run scripts/tree-view/main.go > tree_view_output.html
package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/treeview"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

func main() {
	c := config.CurrentConfig()

	// Build example tree data
	data := buildExampleTreeData()

	// Render tree view HTML — this is exactly what IDEs receive
	treeRenderer, err := treeview.NewTreeHtmlRenderer(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating tree renderer: %v\n", err)
		os.Exit(1)
	}
	html := treeRenderer.RenderTreeView(data)

	// Simulate IDE-side placeholder replacement (exactly as IDEs do it)
	html = replaceIDEPlaceholders(html)

	fmt.Fprintln(os.Stdout, html)
}

// replaceIDEPlaceholders simulates the placeholder replacement that each IDE
// performs before rendering the HTML in a WebView. This is the same mechanism
// used for ${ideStyle}, ${ideScript}, ${nonce} in all Snyk HTML panels.
func replaceIDEPlaceholders(html string) string {
	// Replace nonce placeholder with a demo value
	html = strings.ReplaceAll(html, "${nonce}", "demo-nonce-12345")

	// Replace ${ideStyle} — IDEs inject their theme CSS here.
	// We provide a dark-theme style similar to VS Code's default dark theme.
	ideStyle := `<style nonce="demo-nonce-12345">
    /* Simulated IDE-injected theme (VS Code Dark+) */
    body {
      background-color: #252526;
      color: #cccccc;
    }
    .tree-node-row:hover {
      background-color: rgba(255, 255, 255, 0.05) !important;
    }
    .tree-node-issue .tree-node-row:hover {
      background-color: rgba(0, 102, 204, 0.15) !important;
    }
    .tree-description {
      color: #888888 !important;
    }
    .badge-ignored {
      background-color: #3c3c3c !important;
      color: #888888 !important;
    }
    .badge-new {
      background-color: #1a3a5c !important;
      color: #4da6ff !important;
    }
  </style>`
	html = strings.ReplaceAll(html, "${ideStyle}", ideStyle)

	// Replace ${ideScript} — IDEs inject their JS bridge here.
	// We provide a demo bridge that logs navigation events to the console
	// and shows an alert, simulating the IDE opening a file.
	ideScript := `<script nonce="demo-nonce-12345">
    // Simulated IDE JS bridge — in a real IDE, this opens the file in the editor
    window.__ideTreeNavigateToFile__ = function(filePath, startLine, endLine, startChar, endChar) {
      console.log('[IDE Bridge] Navigate to:', filePath, 'range:', startLine + ':' + startChar, '-', endLine + ':' + endChar);
      alert('IDE would open: ' + filePath + '\nLine ' + startLine + ', Col ' + startChar);
    };
  </script>`
	html = strings.ReplaceAll(html, "${ideScript}", ideScript)

	return html
}

func buildExampleTreeData() treeview.TreeViewData {
	builder := treeview.NewTreeBuilder()

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeCodeSecurity: true,
		product.FilterableIssueTypeOpenSource:   true,
	}

	// Folder 1: my-app (Code + OSS issues)
	folder1Issues := groupIssuesByFile(exampleFolder1Issues())

	// Folder 2: shared-lib (OSS issues only)
	folder2Issues := groupIssuesByFile(exampleFolder2Issues())

	return builder.BuildTreeFromFolderData([]treeview.FolderData{
		{
			FolderPath:          "/Users/dev/workspace/my-app",
			FolderName:          "my-app",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           folder1Issues,
			FilteredIssues:      folder1Issues,
		},
		{
			FolderPath:          "/Users/dev/workspace/shared-lib",
			FolderName:          "shared-lib",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           folder2Issues,
			FilteredIssues:      folder2Issues,
		},
	})
}

func groupIssuesByFile(issues []types.Issue) snyk.IssuesByFile {
	result := snyk.IssuesByFile{}
	for _, issue := range issues {
		fp := issue.GetAffectedFilePath()
		result[fp] = append(result[fp], issue)
	}
	return result
}

// exampleFolder1Issues returns Code + OSS issues for the "my-app" folder.
// Demonstrates: all severities, ignored issues, fixable (AI fix), fixable (upgradable), new issues.
func exampleFolder1Issues() []types.Issue {
	snykURL, _ := url.Parse("https://security.snyk.io/vuln/SNYK-JS-LODASH-590103")
	return []types.Issue{
		// Code: critical, fixable via AI fix
		&snyk.Issue{
			ID:               "javascript/SqlInjection",
			Severity:         types.Critical,
			IssueType:        types.CodeSecurityVulnerability,
			Range:            types.Range{Start: types.Position{Line: 42, Character: 10}, End: types.Position{Line: 42, Character: 45}},
			Message:          "Unsanitized input from an HTTP parameter flows into sql.query.",
			AffectedFilePath: "/Users/dev/workspace/my-app/src/api/users.js",
			Product:          product.ProductCode,
			AdditionalData: snyk.CodeIssueData{
				Key:      "sql-key-1",
				Title:    "SQL Injection",
				CWE:      []string{"CWE-89"},
				HasAIFix: true, // makes IsFixable() return true
			},
		},
		// Code: high, not fixable
		&snyk.Issue{
			ID:               "javascript/Xss",
			Severity:         types.High,
			IssueType:        types.CodeSecurityVulnerability,
			Range:            types.Range{Start: types.Position{Line: 15, Character: 5}, End: types.Position{Line: 15, Character: 30}},
			Message:          "Unsanitized input flows into innerHTML.",
			AffectedFilePath: "/Users/dev/workspace/my-app/src/views/profile.js",
			Product:          product.ProductCode,
			AdditionalData: snyk.CodeIssueData{
				Key:   "xss-key-1",
				Title: "Cross-site Scripting (XSS)",
				CWE:   []string{"CWE-79"},
			},
		},
		// Code: medium, ignored
		&snyk.Issue{
			ID:               "javascript/HardcodedSecret",
			Severity:         types.Medium,
			IssueType:        types.CodeSecurityVulnerability,
			Range:            types.Range{Start: types.Position{Line: 3, Character: 0}, End: types.Position{Line: 3, Character: 50}},
			Message:          "A hardcoded secret was found in the source code.",
			AffectedFilePath: "/Users/dev/workspace/my-app/src/config/db.js",
			Product:          product.ProductCode,
			IsIgnored:        true,
			AdditionalData: snyk.CodeIssueData{
				Key:   "secret-key-1",
				Title: "Use of Hardcoded Credentials",
				CWE:   []string{"CWE-798"},
			},
		},
		// OSS: high, fixable (satisfies IsFixable: IsUpgradable + IsPatchable + UpgradePath + From)
		&snyk.Issue{
			ID:                  "SNYK-JS-LODASH-590103",
			Severity:            types.High,
			IssueType:           types.DependencyVulnerability,
			Range:               types.Range{Start: types.Position{Line: 10}, End: types.Position{Line: 10, Character: 20}},
			Message:             "Prototype Pollution in lodash",
			AffectedFilePath:    "/Users/dev/workspace/my-app/package.json",
			Product:             product.ProductOpenSource,
			IssueDescriptionURL: snykURL,
			AdditionalData: snyk.OssIssueData{
				Key:          "lodash-key-1",
				Title:        "Prototype Pollution",
				Name:         "lodash",
				Version:      "4.17.15",
				FixedIn:      []string{"4.17.21"},
				IsUpgradable: true,
				IsPatchable:  true,
				From:         []string{"my-app@1.0.0", "lodash@4.17.15"},
				UpgradePath:  []any{false, "lodash@4.17.21"},
				Identifiers:  snyk.Identifiers{CVE: []string{"CVE-2020-8203"}},
			},
		},
		// OSS: critical, new issue, not fixable
		&snyk.Issue{
			ID:               "SNYK-JS-EXPRESSFILEUPLOAD-595969",
			Severity:         types.Critical,
			IssueType:        types.DependencyVulnerability,
			Range:            types.Range{Start: types.Position{Line: 15}, End: types.Position{Line: 15, Character: 30}},
			Message:          "Denial of Service (DoS) in express-fileupload",
			AffectedFilePath: "/Users/dev/workspace/my-app/package.json",
			Product:          product.ProductOpenSource,
			IsNew:            true,
			AdditionalData: snyk.OssIssueData{
				Key:         "upload-key-1",
				Title:       "Denial of Service (DoS)",
				Name:        "express-fileupload",
				Version:     "1.1.7",
				FixedIn:     []string{"1.3.1"},
				Identifiers: snyk.Identifiers{CVE: []string{"CVE-2021-23410"}},
			},
		},
		// OSS: low, not fixable
		&snyk.Issue{
			ID:               "SNYK-JS-MINIMIST-559764",
			Severity:         types.Low,
			IssueType:        types.DependencyVulnerability,
			Range:            types.Range{Start: types.Position{Line: 22}, End: types.Position{Line: 22, Character: 20}},
			Message:          "Prototype Pollution in minimist",
			AffectedFilePath: "/Users/dev/workspace/my-app/package.json",
			Product:          product.ProductOpenSource,
			AdditionalData: snyk.OssIssueData{
				Key:         "minimist-key-1",
				Title:       "Prototype Pollution",
				Name:        "minimist",
				Version:     "1.2.0",
				FixedIn:     []string{"1.2.6"},
				Identifiers: snyk.Identifiers{CVE: []string{"CVE-2020-7598"}},
			},
		},
	}
}

// exampleFolder2Issues returns OSS issues for the "shared-lib" folder.
// Demonstrates: multi-root workspace, ignored OSS issue, fixable OSS issue.
func exampleFolder2Issues() []types.Issue {
	return []types.Issue{
		// OSS: high, fixable + ignored
		&snyk.Issue{
			ID:               "SNYK-PYTHON-REQUESTS-5595532",
			Severity:         types.High,
			IssueType:        types.DependencyVulnerability,
			Range:            types.Range{Start: types.Position{Line: 5}, End: types.Position{Line: 5, Character: 20}},
			Message:          "Information Disclosure in requests",
			AffectedFilePath: "/Users/dev/workspace/shared-lib/requirements.txt",
			Product:          product.ProductOpenSource,
			IsIgnored:        true,
			AdditionalData: snyk.OssIssueData{
				Key:          "requests-key-1",
				Title:        "Information Disclosure",
				Name:         "requests",
				Version:      "2.25.0",
				FixedIn:      []string{"2.31.0"},
				IsUpgradable: true,
				IsPatchable:  true,
				From:         []string{"shared-lib@0.1.0", "requests@2.25.0"},
				UpgradePath:  []any{false, "requests@2.31.0"},
				Identifiers:  snyk.Identifiers{CVE: []string{"CVE-2023-32681"}},
			},
		},
		// OSS: medium, not fixable
		&snyk.Issue{
			ID:               "SNYK-PYTHON-PYYAML-590151",
			Severity:         types.Medium,
			IssueType:        types.DependencyVulnerability,
			Range:            types.Range{Start: types.Position{Line: 8}, End: types.Position{Line: 8, Character: 15}},
			Message:          "Arbitrary Code Execution in PyYAML",
			AffectedFilePath: "/Users/dev/workspace/shared-lib/requirements.txt",
			Product:          product.ProductOpenSource,
			AdditionalData: snyk.OssIssueData{
				Key:         "pyyaml-key-1",
				Title:       "Arbitrary Code Execution",
				Name:        "PyYAML",
				Version:     "5.3",
				Identifiers: snyk.Identifiers{CVE: []string{"CVE-2020-14343"}},
			},
		},
	}
}
