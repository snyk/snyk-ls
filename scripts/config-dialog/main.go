/*
 * © 2022-2025 Snyk Limited
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

// ABOUTME: Manual test script to generate configuration dialog HTML for visual inspection
// ABOUTME: Run with: go run scripts/config-dialog/main.go > config_output.html
package main

import (
	"fmt"
	"os"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/configuration"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

func main() {
	// Initialize config
	c := config.CurrentConfig()
	c.SetToken("test-token-12345")
	c.SetOrganization("test-org-uuid")

	// Set integration name to test Visual Studio vs other IDEs
	// Change this to "VISUAL_STUDIO" to test Solution label
	c.SetIntegrationName("VISUAL_STUDIO")
	c.SetIntegrationVersion("1.0.0")

	// Create workspace with folders matching the FolderConfigs below
	// This ensures folder settings are visible in the generated HTML
	notifier := notification.NewNotifier()
	instrumentor := performance.NewInstrumentor()
	testScanner := scanner.NewTestScanner()
	hoverService := hover.NewDefaultService(c)
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	featureFlagService := featureflag.New(c)

	w := workspace.New(c, instrumentor, testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService)

	// Add folders matching the FolderConfig paths
	folder1 := workspace.NewFolder(c, "/Users/username/workspace/my-project", "my-project", testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService)
	folder2 := workspace.NewFolder(c, "/Users/username/workspace/your-project", "your-project", testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService)
	w.AddFolder(folder1)
	w.AddFolder(folder2)

	c.SetWorkspace(w)

	// Create renderer
	renderer, err := configuration.NewConfigHtmlRenderer(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating renderer: %v\n", err)
		os.Exit(1)
	}

	// Create sample settings with folder configs
	settings := types.Settings{
		Token:                  c.Token(),
		Endpoint:               c.Endpoint(),
		Organization:           c.Organization(),
		AuthenticationMethod:   "token",
		Insecure:               "false",
		ActivateSnykOpenSource: "true",
		ActivateSnykCode:       "true",
		ActivateSnykIac:        "true",
		ScanningMode:           "auto",
		AdditionalParams:       "--severity-threshold=high",
		IntegrationName:        c.IntegrationName(),
		IntegrationVersion:     c.IdeVersion(),
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:           "/Users/username/workspace/my-project",
				AdditionalParameters: []string{"--all-projects", "--detection-depth=3"},
				PreferredOrg:         "my-org-uuid-12345",
				AutoDeterminedOrg:    "auto-org-uuid-67890",
				RiskScoreThreshold:   500,
				OrgSetByUser:         true,
				// Add ScanCommandConfig to reproduce template error
				ScanCommandConfig: map[product.Product]types.ScanCommandConfig{
					product.ProductOpenSource: {
						PreScanCommand:              "npm install",
						PostScanCommand:             "npm test",
						PreScanOnlyReferenceFolder:  true,
						PostScanOnlyReferenceFolder: false,
					},
					product.ProductCode: {
						PreScanCommand:              "echo 'code scan'",
						PostScanOnlyReferenceFolder: false,
					},
					product.ProductInfrastructureAsCode: {
						PreScanCommand: "terraform init",
					},
				},
			},
			{
				FolderPath:         "/Users/username/workspace/your-project",
				PreferredOrg:       "manual-org-uuid-11111",
				AutoDeterminedOrg:  "auto-determined-uuid-99999",
				RiskScoreThreshold: 800,
				OrgSetByUser:       false,
			},
		},
	}

	// Add filter severity
	settings.FilterSeverity = &types.SeverityFilter{
		Critical: true,
		High:     false,
		Medium:   true,
		Low:      false,
	}

	// Add issue view options
	settings.IssueViewOptions = &types.IssueViewOptions{
		OpenIssues:    true,
		IgnoredIssues: false,
	}

	// Render HTML
	html := renderer.GetConfigHtml(settings)
	if html == "" {
		fmt.Fprintf(os.Stderr, "Error: Failed to generate HTML\n")
		os.Exit(1)
	}

	// Add test script for dirty tracking demonstration
	testScript := `
	<script nonce="ideNonce">
		// Test handler for dirty state changes
		window.__onFormDirtyChange__ = function(isDirty) {
			var message = isDirty
				? "⚠️ FORM IS DIRTY - You have unsaved changes!"
				: "✅ FORM IS CLEAN - All changes saved";
			alert(message);
		};

		// Mock save function for testing
		window.__saveIdeConfig__ = function(jsonString) {
			alert("💾 Configuration saved!");
		};

		// Mock login/logout for testing
		window.__ideLogin__ = function() {
			alert("🔐 Login triggered");
		};

		window.__ideLogout__ = function() {
			alert("🚪 Logout triggered");
		};
	</script>
</body>
</html>`

	// Replace closing tags with test script
	html = html[:len(html)-len("</body>\n</html>")-1] + testScript

	// Output HTML
	fmt.Println(html)
}
