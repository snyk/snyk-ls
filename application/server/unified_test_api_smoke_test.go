/*
 * © 2025 Snyk Limited
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

package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/server"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

const (
	tokenSecretNameForRiskScore = "SNYK_TOKEN_OSTEST"
	FeatureFlagRiskScore        = "internal_snyk_cli_experimental_risk_score"
	FeatureFlagRiskScoreInCLI   = "internal_snyk_cli_experimental_risk_score_in_cli"
)

func TestUnifiedTestApiSmokeTest(t *testing.T) {
	// Results captured from the first two sub-tests for comparison
	// You must run the first two sub-tests before running the third sub-test
	unifiedTestStarted := false
	var unifiedDiagnostics []types.Diagnostic
	legacyTestStarted := false
	var legacyDiagnostics []types.Diagnostic
	dir := t.TempDir()

	t.Run("1. Unified Test API scan (with risk score)", func(t *testing.T) {
		unifiedTestStarted = true
		unifiedDiagnostics = runOSSComparisonTest(t, true, dir)
	})

	t.Run("2. Legacy scan (without risk score)", func(t *testing.T) {
		legacyTestStarted = true
		legacyDiagnostics = runOSSComparisonTest(t, false, dir)
	})

	t.Run("3. Compare diagnostics from both scans", func(t *testing.T) {
		_ = testutil.SmokeTest(t, tokenSecretNameForRiskScore)

		if !unifiedTestStarted || !legacyTestStarted {
			t.Fatalf("One or both of the sub-tests were not run: unifiedTestStarted=%v, legacyTestStarted=%v", unifiedTestStarted, legacyTestStarted)
		}

		if len(unifiedDiagnostics) == 0 && len(legacyDiagnostics) == 0 {
			t.Fatalf("No diagnostics to compare - previous sub-tests may have failed: unifiedDiagnostics=%d, legacyDiagnostics=%d", len(unifiedDiagnostics), len(legacyDiagnostics))
		}

		compareResult := compareAndReportDiagnostics(t, unifiedDiagnostics, legacyDiagnostics)
		if !compareResult.Match {
			t.Logf("Diagnostics comparison failed:\n%s", compareResult.Report)
		}
	})
}

func runOSSComparisonTest(t *testing.T, unifiedScan bool, dir string) []types.Diagnostic {
	t.Helper()

	c, loc, jsonRPCRecorder := setupOSSComparisonTest(t)
	defer func() {
		_ = loc.Client.Close()
		loc.Server.Stop()
	}()

	// -----------------------------------------
	// setup test repo
	// -----------------------------------------
	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(dir), testsupport.NodejsGoof, "0336589", c.Logger(), true)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	cloneTargetDirString := (string)(cloneTargetDir)

	// -----------------------------------------
	// initialize language server
	// -----------------------------------------
	manifestFile := "package.json"

	initParams := prepareInitParams(t, cloneTargetDir, c)
	ensureInitialized(t, c, loc, initParams, func(c *config.Config) {
		substituteDepGraphFlow(t, c, cloneTargetDirString, manifestFile)
		c.SetAutomaticScanning(false)
		c.SetDeltaFindingsEnabled(false)
	})

	require.Eventuallyf(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.folderConfigs")
		return receivedFolderConfigNotification(t, notifications, cloneTargetDir)
	}, time.Minute, time.Millisecond, "did not receive folder configs")

	if t.Failed() {
		t.FailNow()
	}

	// -----------------------------------------
	// Set feature flags
	// -----------------------------------------
	setRiskScoreFeatureFlagsFromGafConfig(t, c, cloneTargetDirString, unifiedScan)

	// -----------------------------------------
	// Scan
	// -----------------------------------------
	_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   "snyk.workspaceFolder.scan",
		Arguments: []any{cloneTargetDirString},
	})

	require.NoError(t, err)

	waitForScan(t, cloneTargetDirString, c)

	// Check scan completed successfully (fails fast if scan returned error)
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductOpenSource)

	testPath := types.FilePath(filepath.Join(cloneTargetDirString, manifestFile))

	// Wait for diagnostics to be published
	require.Eventually(t, checkForPublishedDiagnostics(t, c, testPath, -1, jsonRPCRecorder), 2*time.Minute, time.Second)

	diagnosticsNotifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
	require.NotEmpty(t, diagnosticsNotifications, "expected at least one notification")

	return extractDiagnostics(t, diagnosticsNotifications, testPath)
}

func setupOSSComparisonTest(t *testing.T) (*config.Config, server.Local, *testsupport.JsonRPCRecorder) {
	t.Helper()
	c := testutil.SmokeTest(t, tokenSecretNameForRiskScore)
	testutil.CreateDummyProgressListener(t)
	endpoint := os.Getenv("SNYK_API")
	if endpoint == "" {
		t.Setenv("SNYK_API", "https://api.snyk.io")
	}

	if endpoint != "" && endpoint != "/v1" {
		t.Setenv("SNYK_API", endpoint)
	}
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(true)
	cleanupChannels()
	di.Init()
	return c, loc, jsonRPCRecorder
}

func setRiskScoreFeatureFlagsFromGafConfig(t *testing.T, c *config.Config, cloneTargetDirString string, enabled bool) {
	t.Helper()

	engine := c.Engine()
	gafConfig := engine.GetConfiguration()
	gafConfig.Set(FeatureFlagRiskScore, enabled)
	gafConfig.Set(FeatureFlagRiskScoreInCLI, enabled)
	folderConfig := c.FolderConfig(types.FilePath(cloneTargetDirString))
	folderConfig.FeatureFlags["useExperimentalRiskScore"] = gafConfig.GetBool(FeatureFlagRiskScore)
	folderConfig.FeatureFlags["useExperimentalRiskScoreInCLI"] = gafConfig.GetBool(FeatureFlagRiskScoreInCLI)
	err := storedconfig.UpdateFolderConfig(gafConfig, folderConfig, c.Logger())
	if err != nil {
		t.Fatal(err, "unable to update folder config")
	}
}

func extractDiagnostics(t *testing.T, notifications []jrpc2.Request, testPath types.FilePath) []types.Diagnostic {
	t.Helper()
	diagnostics := []types.Diagnostic{}
	for _, n := range notifications {
		diagnosticsParams := types.PublishDiagnosticsParams{}
		_ = n.UnmarshalParams(&diagnosticsParams)
		if diagnosticsParams.URI != uri.PathToUri(testPath) {
			// Skip notifications that don't match the test path
			continue
		}
		diagnostics = append(diagnostics, diagnosticsParams.Diagnostics...)
	}
	return diagnostics
}

type ComparisonResult struct {
	Match  bool
	Report string
}

type FieldComparison struct {
	DiagnosticTitle string
	FieldPath       string
	Matched         bool
	UnifiedValue    string
	LegacyValue     string
}

//nolint:gocyclo // High complexity is necessary for thorough field-by-field diagnostic comparison
func compareAndReportDiagnostics(t *testing.T, unified, legacy []types.Diagnostic) ComparisonResult {
	t.Helper()

	var report []string
	match := true
	var allComparisons []FieldComparison

	// Debug logging
	t.Logf("Received %d unified diagnostics and %d legacy diagnostics", len(unified), len(legacy))

	// Helper to get matching key from OssIssueData.Key
	getMatchingKey := func(d types.Diagnostic) string {
		return d.Code.(string) + "|" + d.Range.String()
	}

	// Create maps indexed by OssIssueData.Key for easier comparison
	unifiedMap := make(map[string]types.Diagnostic)
	legacyMap := make(map[string]types.Diagnostic)

	for _, d := range unified {
		key := getMatchingKey(d)
		unifiedMap[key] = d
		// Debug: check AdditionalData type
		if d.Data.AdditionalData != nil {
			t.Logf("Unified diagnostic %s: AdditionalData type = %T", key, d.Data.AdditionalData)
		}
	}

	for _, d := range legacy {
		key := getMatchingKey(d)
		legacyMap[key] = d
		// Debug: check AdditionalData type
		if d.Data.AdditionalData != nil {
			t.Logf("Legacy diagnostic %s: AdditionalData type = %T", key, d.Data.AdditionalData)
		}
	}

	// Check for diagnostics in unified but not in legacy
	for key := range unifiedMap {
		if _, exists := legacyMap[key]; !exists {
			match = false
			report = append(report, "❌ Diagnostic present in unified but missing in legacy:")
			report = append(report, "   Key: "+key)
			allComparisons = append(allComparisons, FieldComparison{
				DiagnosticTitle: key,
				FieldPath:       "_DIAGNOSTIC_",
				Matched:         false,
				UnifiedValue:    "EXISTS",
				LegacyValue:     "MISSING",
			})

			// Extract context fields from the unified diagnostic
			unifiedDiag := unifiedMap[key]
			allComparisons = append(allComparisons, extractContextFieldsFromSingleDiagnostic(key, unifiedDiag, true)...)
		}
	}

	// Check for diagnostics in legacy but not in unified
	for key := range legacyMap {
		if _, exists := unifiedMap[key]; !exists {
			match = false
			report = append(report, "❌ Diagnostic present in legacy but missing in unified:")
			report = append(report, "   Key: "+key)
			allComparisons = append(allComparisons, FieldComparison{
				DiagnosticTitle: key,
				FieldPath:       "_DIAGNOSTIC_",
				Matched:         false,
				UnifiedValue:    "MISSING",
				LegacyValue:     "EXISTS",
			})

			// Extract context fields from the legacy diagnostic
			legacyDiag := legacyMap[key]
			allComparisons = append(allComparisons, extractContextFieldsFromSingleDiagnostic(key, legacyDiag, false)...)
		}
	}

	// Compare matching diagnostics field-by-field
	for key, unifiedDiag := range unifiedMap {
		legacyDiag, exists := legacyMap[key]
		if !exists {
			continue // Already reported above
		}

		fieldComparisons := collectDiagnosticFieldComparisons(key, unifiedDiag, legacyDiag)
		allComparisons = append(allComparisons, fieldComparisons...)

		var differences []string
		for _, fc := range fieldComparisons {
			if !fc.Matched {
				differences = append(differences, formatFieldDiff(fc.FieldPath, fc.UnifiedValue, fc.LegacyValue))
			}
		}

		if len(differences) > 0 {
			match = false
			report = append(report, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			report = append(report, "❌ Differences found for diagnostic: "+key)
			report = append(report, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			report = append(report, differences...)
		}
	}

	if match {
		report = append(report, "✅ All diagnostics match perfectly!")
	}

	// Log comparison stats
	t.Logf("Generated %d field comparisons for %d unified and %d legacy diagnostics",
		len(allComparisons), len(unified), len(legacy))

	// Write comparison files
	if err := writeComparisonFiles(t, allComparisons); err != nil {
		t.Logf("Warning: Failed to write comparison files: %v", err)
	} else {
		t.Logf("Successfully wrote comparison files")
	}

	return ComparisonResult{
		Match:  match,
		Report: joinStrings(report, "\n"),
	}
}

func collectDiagnosticFieldComparisons(title string, unified, legacy types.Diagnostic) []FieldComparison {
	var comparisons []FieldComparison

	// ONLY collect mismatches to reduce output (except for key fields like Range, PackageName, Version)

	// ALWAYS output Range (even if matching)
	rangeStartMatched := unified.Range.Start == legacy.Range.Start
	comparisons = append(comparisons, FieldComparison{
		DiagnosticTitle: title,
		FieldPath:       "Range.Start",
		Matched:         rangeStartMatched,
		UnifiedValue:    formatPosition(unified.Range.Start),
		LegacyValue:     formatPosition(legacy.Range.Start),
	})

	rangeEndMatched := unified.Range.End == legacy.Range.End
	comparisons = append(comparisons, FieldComparison{
		DiagnosticTitle: title,
		FieldPath:       "Range.End",
		Matched:         rangeEndMatched,
		UnifiedValue:    formatPosition(unified.Range.End),
		LegacyValue:     formatPosition(legacy.Range.End),
	})

	// Compare Severity
	if unified.Severity != legacy.Severity {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Severity",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Severity),
			LegacyValue:     formatAny(legacy.Severity),
		})
	}

	// Compare Code
	if !compareAny(unified.Code, legacy.Code) {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Code",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Code),
			LegacyValue:     formatAny(legacy.Code),
		})
	}

	// Compare Source
	if unified.Source != legacy.Source {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Source",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Source),
			LegacyValue:     formatAny(legacy.Source),
		})
	}

	// Compare Message
	if unified.Message != legacy.Message {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Message",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Message),
			LegacyValue:     formatAny(legacy.Message),
		})
	}

	// Compare CodeDescription
	if unified.CodeDescription != legacy.CodeDescription {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "CodeDescription.Href",
			Matched:         false,
			UnifiedValue:    formatAny(unified.CodeDescription.Href),
			LegacyValue:     formatAny(legacy.CodeDescription.Href),
		})
	}

	// Compare Tags
	if !compareTags(unified.Tags, legacy.Tags) {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Tags",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Tags),
			LegacyValue:     formatAny(legacy.Tags),
		})
	}

	// Compare RelatedInformation (only mismatches)
	comparisons = append(comparisons, collectRelatedInformationComparisons(title, unified.RelatedInformation, legacy.RelatedInformation)...)

	// Compare Data (ScanIssue) fields (only mismatches)
	comparisons = append(comparisons, collectScanIssueComparisons(title, unified.Data, legacy.Data)...)

	return comparisons
}

func collectRelatedInformationComparisons(title string, unified, legacy []types.DiagnosticRelatedInformation) []FieldComparison {
	var comparisons []FieldComparison

	// Compare length - only add if mismatch
	if len(unified) != len(legacy) {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "RelatedInformation.Length",
			Matched:         false,
			UnifiedValue:    fmt.Sprintf("%d", len(unified)),
			LegacyValue:     fmt.Sprintf("%d", len(legacy)),
		})
	}

	// Compare each item - only add mismatches
	maxLen := len(unified)
	if len(legacy) > maxLen {
		maxLen = len(legacy)
	}

	for i := 0; i < maxLen; i++ {
		var unifiedLoc, legacyLoc, unifiedMsg, legacyMsg string
		var hasUnified, hasLegacy bool

		if i < len(unified) {
			hasUnified = true
			unifiedLoc = fmt.Sprintf("%v", unified[i].Location)
			unifiedMsg = unified[i].Message
		} else {
			unifiedLoc = "MISSING"
			unifiedMsg = "MISSING"
		}

		if i < len(legacy) {
			hasLegacy = true
			legacyLoc = fmt.Sprintf("%v", legacy[i].Location)
			legacyMsg = legacy[i].Message
		} else {
			legacyLoc = "MISSING"
			legacyMsg = "MISSING"
		}

		// Only add if location doesn't match
		if !hasUnified || !hasLegacy || unified[i].Location != legacy[i].Location {
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("RelatedInformation[%d].Location", i),
				Matched:         false,
				UnifiedValue:    unifiedLoc,
				LegacyValue:     legacyLoc,
			})
		}

		// Only add if message doesn't match
		if !hasUnified || !hasLegacy || unified[i].Message != legacy[i].Message {
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("RelatedInformation[%d].Message", i),
				Matched:         false,
				UnifiedValue:    unifiedMsg,
				LegacyValue:     legacyMsg,
			})
		}
	}

	return comparisons
}

//nolint:gocyclo // High complexity due to many field-by-field comparisons needed for thorough scan issue validation
func collectScanIssueComparisons(title string, unified, legacy types.ScanIssue) []FieldComparison {
	var comparisons []FieldComparison

	// Only add mismatches
	if unified.Id != legacy.Id {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.Id",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Id),
			LegacyValue:     formatAny(legacy.Id),
		})
	}

	if unified.Title != legacy.Title {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.Title",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Title),
			LegacyValue:     formatAny(legacy.Title),
		})
	}

	if unified.Severity != legacy.Severity {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.Severity",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Severity),
			LegacyValue:     formatAny(legacy.Severity),
		})
	}

	if unified.FilePath != legacy.FilePath {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.FilePath",
			Matched:         false,
			UnifiedValue:    formatAny(unified.FilePath),
			LegacyValue:     formatAny(legacy.FilePath),
		})
	}

	if unified.ContentRoot != legacy.ContentRoot {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.ContentRoot",
			Matched:         false,
			UnifiedValue:    formatAny(unified.ContentRoot),
			LegacyValue:     formatAny(legacy.ContentRoot),
		})
	}

	// Compare Data.Range (separate from Diagnostic.Range)
	if unified.Range.Start != legacy.Range.Start {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.Range.Start",
			Matched:         false,
			UnifiedValue:    formatPosition(unified.Range.Start),
			LegacyValue:     formatPosition(legacy.Range.Start),
		})
	}

	if unified.Range.End != legacy.Range.End {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.Range.End",
			Matched:         false,
			UnifiedValue:    formatPosition(unified.Range.End),
			LegacyValue:     formatPosition(legacy.Range.End),
		})
	}

	if unified.IsIgnored != legacy.IsIgnored {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.IsIgnored",
			Matched:         false,
			UnifiedValue:    formatAny(unified.IsIgnored),
			LegacyValue:     formatAny(legacy.IsIgnored),
		})
	}

	if unified.IsNew != legacy.IsNew {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.IsNew",
			Matched:         false,
			UnifiedValue:    formatAny(unified.IsNew),
			LegacyValue:     formatAny(legacy.IsNew),
		})
	}

	// Compare IgnoreDetails fields (only mismatches)
	comparisons = append(comparisons, collectIgnoreDetailsComparisons(title, unified.IgnoreDetails, legacy.IgnoreDetails)...)

	if unified.FilterableIssueType != legacy.FilterableIssueType {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.FilterableIssueType",
			Matched:         false,
			UnifiedValue:    formatAny(unified.FilterableIssueType),
			LegacyValue:     formatAny(legacy.FilterableIssueType),
		})
	}

	// Compare AdditionalData - if it's OssIssueData, compare all fields
	if unifiedOss, unifiedOk := unified.AdditionalData.(types.OssIssueData); unifiedOk {
		if legacyOss, legacyOk := legacy.AdditionalData.(types.OssIssueData); legacyOk {
			comparisons = append(comparisons, collectOssIssueDataComparisons(title, unifiedOss, legacyOss)...)
		} else {
			// Type mismatch
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       "Data.AdditionalData.Type",
				Matched:         false,
				UnifiedValue:    "OssIssueData",
				LegacyValue:     "OTHER_TYPE",
			})
		}
	} else {
		// AdditionalData might be unmarshaled as map[string]interface{} from JSON
		// Try to convert it to OssIssueData for field-by-field comparison
		unifiedOss, unifiedConverted := convertMapToOssIssueData(unified.AdditionalData)
		legacyOss, legacyConverted := convertMapToOssIssueData(legacy.AdditionalData)

		if unifiedConverted && legacyConverted {
			// Successfully converted both, do field-by-field comparison
			comparisons = append(comparisons, collectOssIssueDataComparisons(title, unifiedOss, legacyOss)...)
		} else {
			// Not OssIssueData, just compare generically - only add if mismatch
			if !compareAny(unified.AdditionalData, legacy.AdditionalData) {
				comparisons = append(comparisons, FieldComparison{
					DiagnosticTitle: title,
					FieldPath:       "Data.AdditionalData",
					Matched:         false,
					UnifiedValue:    formatAny(unified.AdditionalData),
					LegacyValue:     formatAny(legacy.AdditionalData),
				})
			}
		}
	}

	return comparisons
}

func collectIgnoreDetailsComparisons(title string, unified, legacy types.IgnoreDetails) []FieldComparison {
	var comparisons []FieldComparison

	// Only add mismatches
	if unified.Category != legacy.Category {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.IgnoreDetails.Category",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Category),
			LegacyValue:     formatAny(legacy.Category),
		})
	}

	if unified.Reason != legacy.Reason {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.IgnoreDetails.Reason",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Reason),
			LegacyValue:     formatAny(legacy.Reason),
		})
	}

	if unified.Expiration != legacy.Expiration {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.IgnoreDetails.Expiration",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Expiration),
			LegacyValue:     formatAny(legacy.Expiration),
		})
	}

	if !unified.IgnoredOn.Equal(legacy.IgnoredOn) {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.IgnoreDetails.IgnoredOn",
			Matched:         false,
			UnifiedValue:    formatAny(unified.IgnoredOn),
			LegacyValue:     formatAny(legacy.IgnoredOn),
		})
	}

	if unified.IgnoredBy != legacy.IgnoredBy {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.IgnoreDetails.IgnoredBy",
			Matched:         false,
			UnifiedValue:    formatAny(unified.IgnoredBy),
			LegacyValue:     formatAny(legacy.IgnoredBy),
		})
	}

	if unified.Status != legacy.Status {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.IgnoreDetails.Status",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Status),
			LegacyValue:     formatAny(legacy.Status),
		})
	}

	return comparisons
}

//nolint:gocyclo // High complexity due to many field comparisons needed for thorough OSS issue data validation
func collectOssIssueDataComparisons(title string, unified, legacy types.OssIssueData) []FieldComparison {
	var comparisons []FieldComparison

	// Only add mismatches
	if unified.Key != legacy.Key {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.Key",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Key),
			LegacyValue:     formatAny(legacy.Key),
		})
	}

	if unified.RuleId != legacy.RuleId {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.RuleId",
			Matched:         false,
			UnifiedValue:    formatAny(unified.RuleId),
			LegacyValue:     formatAny(legacy.RuleId),
		})
	}

	if unified.License != legacy.License {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.License",
			Matched:         false,
			UnifiedValue:    formatAny(unified.License),
			LegacyValue:     formatAny(legacy.License),
		})
	}

	// Compare Identifiers sub-object (only mismatches)
	comparisons = append(comparisons, collectOssIdentifiersComparisons(title, unified.Identifiers, legacy.Identifiers)...)

	if unified.Description[0:20] != legacy.Description[0:20] {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.Description",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Description),
			LegacyValue:     formatAny(legacy.Description),
		})
	}

	if unified.Language != legacy.Language {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.Language",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Language),
			LegacyValue:     formatAny(legacy.Language),
		})
	}

	if unified.PackageManager != legacy.PackageManager {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.PackageManager",
			Matched:         false,
			UnifiedValue:    formatAny(unified.PackageManager),
			LegacyValue:     formatAny(legacy.PackageManager),
		})
	}

	// ALWAYS output PackageName (even if matching) for context
	packageNameMatched := unified.PackageName == legacy.PackageName
	comparisons = append(comparisons, FieldComparison{
		DiagnosticTitle: title,
		FieldPath:       "Data.AdditionalData.PackageName",
		Matched:         packageNameMatched,
		UnifiedValue:    formatAny(unified.PackageName),
		LegacyValue:     formatAny(legacy.PackageName),
	})

	if unified.Name != legacy.Name {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.Name",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Name),
			LegacyValue:     formatAny(legacy.Name),
		})
	}

	// ALWAYS output Version (even if matching) for context
	versionMatched := unified.Version == legacy.Version
	comparisons = append(comparisons, FieldComparison{
		DiagnosticTitle: title,
		FieldPath:       "Data.AdditionalData.Version",
		Matched:         versionMatched,
		UnifiedValue:    formatAny(unified.Version),
		LegacyValue:     formatAny(legacy.Version),
	})

	if unified.Exploit != legacy.Exploit {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.Exploit",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Exploit),
			LegacyValue:     formatAny(legacy.Exploit),
		})
	}

	if unified.CVSSv3 != legacy.CVSSv3 {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.CVSSv3",
			Matched:         false,
			UnifiedValue:    formatAny(unified.CVSSv3),
			LegacyValue:     formatAny(legacy.CVSSv3),
		})
	}

	if unified.CvssScore != legacy.CvssScore {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.CvssScore",
			Matched:         false,
			UnifiedValue:    formatAny(unified.CvssScore),
			LegacyValue:     formatAny(legacy.CvssScore),
		})
	}

	// Compare CvssSources array (only mismatches)
	comparisons = append(comparisons, collectCvssSourcesComparisons(title, unified.CvssSources, legacy.CvssSources)...)

	// Compare FixedIn array (only mismatches)
	comparisons = append(comparisons, collectStringArrayComparison(title, "Data.AdditionalData.FixedIn", unified.FixedIn, legacy.FixedIn)...)

	// ALWAYS output introducing package (from[1]) for context - this determines the diagnostic range
	unifiedIntroducingPkg := ""
	legacyIntroducingPkg := ""
	if len(unified.From) > 1 {
		unifiedIntroducingPkg = unified.From[1]
	}
	if len(legacy.From) > 1 {
		legacyIntroducingPkg = legacy.From[1]
	}
	introducingPkgMatched := unifiedIntroducingPkg == legacyIntroducingPkg
	comparisons = append(comparisons, FieldComparison{
		DiagnosticTitle: title,
		FieldPath:       "Data.AdditionalData.From[1] (Introducing Package)",
		Matched:         introducingPkgMatched,
		UnifiedValue:    formatAny(unifiedIntroducingPkg),
		LegacyValue:     formatAny(legacyIntroducingPkg),
	})

	// Extract and ALWAYS show introducing package name and version separately
	unifiedIntroName, unifiedIntroVersion := parsePackageNameVersion(unifiedIntroducingPkg)
	legacyIntroName, legacyIntroVersion := parsePackageNameVersion(legacyIntroducingPkg)

	introNameMatched := unifiedIntroName == legacyIntroName
	comparisons = append(comparisons, FieldComparison{
		DiagnosticTitle: title,
		FieldPath:       "Data.AdditionalData.From[1].Name (Introducing Package Name)",
		Matched:         introNameMatched,
		UnifiedValue:    formatAny(unifiedIntroName),
		LegacyValue:     formatAny(legacyIntroName),
	})

	introVersionMatched := unifiedIntroVersion == legacyIntroVersion
	comparisons = append(comparisons, FieldComparison{
		DiagnosticTitle: title,
		FieldPath:       "Data.AdditionalData.From[1].Version (Introducing Package Version)",
		Matched:         introVersionMatched,
		UnifiedValue:    formatAny(unifiedIntroVersion),
		LegacyValue:     formatAny(legacyIntroVersion),
	})

	// Compare From array (only mismatches)
	comparisons = append(comparisons, collectStringArrayComparison(title, "Data.AdditionalData.From", unified.From, legacy.From)...)

	// Compare UpgradePath - only add if mismatch
	if !compareAny(unified.UpgradePath, legacy.UpgradePath) {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.UpgradePath",
			Matched:         false,
			UnifiedValue:    formatAny(unified.UpgradePath),
			LegacyValue:     formatAny(legacy.UpgradePath),
		})
	}

	if unified.IsPatchable != legacy.IsPatchable {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.IsPatchable",
			Matched:         false,
			UnifiedValue:    formatAny(unified.IsPatchable),
			LegacyValue:     formatAny(legacy.IsPatchable),
		})
	}

	if unified.IsUpgradable != legacy.IsUpgradable {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.IsUpgradable",
			Matched:         false,
			UnifiedValue:    formatAny(unified.IsUpgradable),
			LegacyValue:     formatAny(legacy.IsUpgradable),
		})
	}

	if unified.ProjectName != legacy.ProjectName {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.ProjectName",
			Matched:         false,
			UnifiedValue:    formatAny(unified.ProjectName),
			LegacyValue:     formatAny(legacy.ProjectName),
		})
	}

	if unified.DisplayTargetFile != legacy.DisplayTargetFile {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.DisplayTargetFile",
			Matched:         false,
			UnifiedValue:    formatAny(unified.DisplayTargetFile),
			LegacyValue:     formatAny(legacy.DisplayTargetFile),
		})
	}

	// Compare MatchingIssues array length - only add if mismatch
	if len(unified.MatchingIssues) != len(legacy.MatchingIssues) {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.MatchingIssues.Length",
			Matched:         false,
			UnifiedValue:    fmt.Sprintf("%d", len(unified.MatchingIssues)),
			LegacyValue:     fmt.Sprintf("%d", len(legacy.MatchingIssues)),
		})
	}

	if unified.Lesson != legacy.Lesson {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.Lesson",
			Matched:         false,
			UnifiedValue:    formatAny(unified.Lesson),
			LegacyValue:     formatAny(legacy.Lesson),
		})
	}

	return comparisons
}

func collectOssIdentifiersComparisons(title string, unified, legacy types.OssIdentifiers) []FieldComparison {
	var comparisons []FieldComparison

	// Compare CWE array
	comparisons = append(comparisons, collectStringArrayComparison(title, "Data.AdditionalData.Identifiers.CWE", unified.CWE, legacy.CWE)...)

	// Compare CVE array
	comparisons = append(comparisons, collectStringArrayComparison(title, "Data.AdditionalData.Identifiers.CVE", unified.CVE, legacy.CVE)...)

	return comparisons
}

func collectCvssSourcesComparisons(title string, unified, legacy []types.CvssSource) []FieldComparison {
	var comparisons []FieldComparison

	// Compare length - only add if mismatch
	if len(unified) != len(legacy) {
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.CvssSources.Length",
			Matched:         false,
			UnifiedValue:    fmt.Sprintf("%d", len(unified)),
			LegacyValue:     fmt.Sprintf("%d", len(legacy)),
		})
	}

	maxLen := len(unified)
	if len(legacy) > maxLen {
		maxLen = len(legacy)
	}

	// Compare each CvssSource - only add mismatches
	for i := 0; i < maxLen; i++ {
		if i >= len(unified) {
			// Unified is missing this item
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("Data.AdditionalData.CvssSources[%d]", i),
				Matched:         false,
				UnifiedValue:    "MISSING",
				LegacyValue:     "EXISTS",
			})
			continue
		}
		if i >= len(legacy) {
			// Legacy is missing this item
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("Data.AdditionalData.CvssSources[%d]", i),
				Matched:         false,
				UnifiedValue:    "EXISTS",
				LegacyValue:     "MISSING",
			})
			continue
		}

		// Compare all fields of CvssSource - only add mismatches
		u := unified[i]
		l := legacy[i]

		if u.Type != l.Type {
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("Data.AdditionalData.CvssSources[%d].Type", i),
				Matched:         false,
				UnifiedValue:    formatAny(u.Type),
				LegacyValue:     formatAny(l.Type),
			})
		}

		if u.Vector != l.Vector {
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("Data.AdditionalData.CvssSources[%d].Vector", i),
				Matched:         false,
				UnifiedValue:    formatAny(u.Vector),
				LegacyValue:     formatAny(l.Vector),
			})
		}

		if u.Assigner != l.Assigner {
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("Data.AdditionalData.CvssSources[%d].Assigner", i),
				Matched:         false,
				UnifiedValue:    formatAny(u.Assigner),
				LegacyValue:     formatAny(l.Assigner),
			})
		}

		if u.Severity != l.Severity {
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("Data.AdditionalData.CvssSources[%d].Severity", i),
				Matched:         false,
				UnifiedValue:    formatAny(u.Severity),
				LegacyValue:     formatAny(l.Severity),
			})
		}

		if u.BaseScore != l.BaseScore {
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("Data.AdditionalData.CvssSources[%d].BaseScore", i),
				Matched:         false,
				UnifiedValue:    formatAny(u.BaseScore),
				LegacyValue:     formatAny(l.BaseScore),
			})
		}

		if u.CvssVersion != l.CvssVersion {
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("Data.AdditionalData.CvssSources[%d].CvssVersion", i),
				Matched:         false,
				UnifiedValue:    formatAny(u.CvssVersion),
				LegacyValue:     formatAny(l.CvssVersion),
			})
		}

		if u.ModificationTime != l.ModificationTime {
			comparisons = append(comparisons, FieldComparison{
				DiagnosticTitle: title,
				FieldPath:       fmt.Sprintf("Data.AdditionalData.CvssSources[%d].ModificationTime", i),
				Matched:         false,
				UnifiedValue:    formatAny(u.ModificationTime),
				LegacyValue:     formatAny(l.ModificationTime),
			})
		}
	}

	return comparisons
}

func collectStringArrayComparison(title, fieldPath string, unified, legacy []string) []FieldComparison {
	var comparisons []FieldComparison

	// Check if arrays match
	arraysMatch := len(unified) == len(legacy)
	if arraysMatch {
		for i := range unified {
			if unified[i] != legacy[i] {
				arraysMatch = false
				break
			}
		}
	}

	// If arrays don't match, output the entire array from both sides
	if !arraysMatch {
		unifiedStr := "["
		for i, v := range unified {
			if i > 0 {
				unifiedStr += ", "
			}
			unifiedStr += fmt.Sprintf("%q", v)
		}
		unifiedStr += "]"

		legacyStr := "["
		for i, v := range legacy {
			if i > 0 {
				legacyStr += ", "
			}
			legacyStr += fmt.Sprintf("%q", v)
		}
		legacyStr += "]"

		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       fieldPath,
			Matched:         false,
			UnifiedValue:    unifiedStr,
			LegacyValue:     legacyStr,
		})
	}

	return comparisons
}

func compareTags(unified, legacy []types.DiagnosticTag) bool {
	if len(unified) != len(legacy) {
		return false
	}

	for i := range unified {
		if unified[i] != legacy[i] {
			return false
		}
	}

	return true
}

func compareAny(a, b any) bool {
	return formatAny(a) == formatAny(b)
}

func formatFieldDiff(fieldName string, unified, legacy any) string {
	return "    " + fieldName + ":\n" +
		"      Unified: " + formatAny(unified) + "\n" +
		"      Legacy:  " + formatAny(legacy)
}

// convertMapToOssIssueData attempts to convert a map[string]interface{} (from JSON unmarshaling)
// to types.OssIssueData for field-by-field comparison
func convertMapToOssIssueData(data any) (types.OssIssueData, bool) {
	if data == nil {
		return types.OssIssueData{}, false
	}

	// If it's already OssIssueData, return it
	if ossData, ok := data.(types.OssIssueData); ok {
		return ossData, true
	}

	// Try to convert from map[string]interface{}
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return types.OssIssueData{}, false
	}

	// Use JSON marshaling/unmarshaling to convert map to struct
	jsonBytes, err := json.Marshal(dataMap)
	if err != nil {
		return types.OssIssueData{}, false
	}

	var ossData types.OssIssueData
	if err := json.Unmarshal(jsonBytes, &ossData); err != nil {
		return types.OssIssueData{}, false
	}

	return ossData, true
}

func formatAny(v any) string {
	if v == nil {
		return "<nil>"
	}
	switch val := v.(type) {
	case string:
		if val == "" {
			return "\"\""
		}
		return fmt.Sprintf("%q", val)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%v", val)
	case float32, float64:
		return fmt.Sprintf("%v", val)
	case bool:
		return fmt.Sprintf("%v", val)
	case types.DiagnosticSeverity:
		return fmt.Sprintf("%d", val)
	case types.DiagnosticTag:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func formatPosition(p sglsp.Position) string {
	return fmt.Sprintf("Line:%d, Char:%d", p.Line, p.Character)
}

// parsePackageNameVersion parses "package@version" or "groupId:artifactId@version" format
func parsePackageNameVersion(pkgString string) (name, version string) {
	if pkgString == "" {
		return "", ""
	}

	// Split by @ to get name and version
	parts := strings.Split(pkgString, "@")
	if len(parts) < 2 {
		return pkgString, ""
	}

	// Handle scoped packages like @org/package@version
	// or Maven packages like groupId:artifactId@version
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	// For scoped packages: @org/package@version splits into ["", "org/package", "version"]
	// Join the first parts back together for the name
	version = parts[len(parts)-1]
	name = strings.Join(parts[:len(parts)-1], "@")
	return name, version
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}

	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}

	return result
}

//nolint:gocyclo // High complexity necessary for grouping, categorizing, and formatting comparison statistics
func writeComparisonFiles(t *testing.T, comparisons []FieldComparison) error {
	t.Helper()

	// Sort by diagnostic title, then by field path
	sort.Slice(comparisons, func(i, j int) bool {
		if comparisons[i].DiagnosticTitle != comparisons[j].DiagnosticTitle {
			return comparisons[i].DiagnosticTitle < comparisons[j].DiagnosticTitle
		}
		return comparisons[i].FieldPath < comparisons[j].FieldPath
	})

	// Write CSV file
	csvFile, err := os.Create("diagnostic_comparison.csv")
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	// Write CSV header
	if writeErr := csvWriter.Write([]string{"Matched", "Diagnostic Title", "Field Path", "Unified Value", "Legacy Value"}); writeErr != nil {
		return fmt.Errorf("failed to write CSV header: %w", writeErr)
	}

	// Write CSV rows
	for _, fc := range comparisons {
		matchedStr := "✅"
		if !fc.Matched {
			matchedStr = "❌"
		}
		if writeErr := csvWriter.Write([]string{
			matchedStr,
			fc.DiagnosticTitle,
			fc.FieldPath,
			fc.UnifiedValue,
			fc.LegacyValue,
		}); writeErr != nil {
			return fmt.Errorf("failed to write CSV row: %w", writeErr)
		}
	}

	// Write Markdown file
	mdFile, err := os.Create("diagnostic_comparison.md")
	if err != nil {
		return fmt.Errorf("failed to create MD file: %w", err)
	}
	defer mdFile.Close()

	// Write MD header
	fmt.Fprintln(mdFile, "# Diagnostic Comparison Report")
	fmt.Fprintln(mdFile, "")

	// Group by matched status and count diagnostics
	matchedComps := []FieldComparison{}
	unmatchedComps := []FieldComparison{}
	diagnosticSet := make(map[string]bool)
	missingInLegacy := make(map[string]bool)
	missingInUnified := make(map[string]bool)

	for _, fc := range comparisons {
		diagnosticSet[fc.DiagnosticTitle] = true
		if fc.FieldPath == "_DIAGNOSTIC_" {
			if fc.UnifiedValue == "EXISTS" && fc.LegacyValue == "MISSING" {
				missingInLegacy[fc.DiagnosticTitle] = true
			} else if fc.UnifiedValue == "MISSING" && fc.LegacyValue == "EXISTS" {
				missingInUnified[fc.DiagnosticTitle] = true
			}
		}

		if fc.Matched {
			matchedComps = append(matchedComps, fc)
		} else {
			unmatchedComps = append(unmatchedComps, fc)
		}
	}

	// Calculate statistics
	totalDiagnostics := len(diagnosticSet)
	matchedDiagnostics := totalDiagnostics - len(missingInLegacy) - len(missingInUnified)
	totalFieldComparisons := len(comparisons)
	matchedFields := len(matchedComps)
	unmatchedFields := len(unmatchedComps)

	// Write statistics section
	fmt.Fprintln(mdFile, "## 📊 Comparison Statistics")
	fmt.Fprintln(mdFile, "")
	fmt.Fprintf(mdFile, "| Metric | Count | Percentage |\n")
	fmt.Fprintf(mdFile, "|--------|-------|------------|\n")
	fmt.Fprintf(mdFile, "| **Total Diagnostics Compared** | %d | - |\n", totalDiagnostics)
	fmt.Fprintf(mdFile, "| Diagnostics in Both Flows | %d | %.1f%% |\n", matchedDiagnostics, float64(matchedDiagnostics)/float64(totalDiagnostics)*100)
	fmt.Fprintf(mdFile, "| Diagnostics Only in Unified | %d | %.1f%% |\n", len(missingInLegacy), float64(len(missingInLegacy))/float64(totalDiagnostics)*100)
	fmt.Fprintf(mdFile, "| Diagnostics Only in Legacy | %d | %.1f%% |\n", len(missingInUnified), float64(len(missingInUnified))/float64(totalDiagnostics)*100)
	fmt.Fprintf(mdFile, "| **Total Field Comparisons** | %d | - |\n", totalFieldComparisons)
	fmt.Fprintf(mdFile, "| Matched Fields | %d | %.1f%% |\n", matchedFields, float64(matchedFields)/float64(totalFieldComparisons)*100)
	fmt.Fprintf(mdFile, "| Unmatched Fields | %d | %.1f%% |\n", unmatchedFields, float64(unmatchedFields)/float64(totalFieldComparisons)*100)
	fmt.Fprintln(mdFile, "")
	fmt.Fprintln(mdFile, "---")
	fmt.Fprintln(mdFile, "")

	// Build a map of key context fields for each diagnostic (to show in both sections)
	contextFields := buildContextFieldsMap(comparisons)

	// Write unmatched section first (more important)
	if len(unmatchedComps) > 0 {
		fmt.Fprintln(mdFile, "## ❌ Unmatched Fields")
		fmt.Fprintln(mdFile, "")
		writeMDSectionWithContext(mdFile, unmatchedComps, contextFields)
	}

	// Write matched section
	if len(matchedComps) > 0 {
		fmt.Fprintln(mdFile, "## ✅ Matched Fields")
		fmt.Fprintln(mdFile, "")
		writeMDSection(mdFile, matchedComps)
	}

	t.Logf("Comparison files written: diagnostic_comparison.csv and diagnostic_comparison.md")
	return nil
}

// buildContextFieldsMap extracts key context fields for each diagnostic
func buildContextFieldsMap(comparisons []FieldComparison) map[string][]FieldComparison {
	contextFieldsMap := make(map[string][]FieldComparison)

	// Key fields that provide context for understanding the diagnostic
	keyFields := map[string]bool{
		"Range.Start":                     true,
		"Range.End":                       true,
		"Data.AdditionalData.PackageName": true,
		"Data.AdditionalData.Version":     true,
		"Data.AdditionalData.From[1] (Introducing Package)":                 true,
		"Data.AdditionalData.From[1].Name (Introducing Package Name)":       true,
		"Data.AdditionalData.From[1].Version (Introducing Package Version)": true,
	}

	for _, fc := range comparisons {
		if keyFields[fc.FieldPath] {
			contextFieldsMap[fc.DiagnosticTitle] = append(contextFieldsMap[fc.DiagnosticTitle], fc)
		}
	}

	return contextFieldsMap
}

// writeMDSectionWithContext writes a section with context fields prepended to each diagnostic
func writeMDSectionWithContext(file *os.File, comparisons []FieldComparison, contextFields map[string][]FieldComparison) {
	currentDiagnostic := ""

	for _, fc := range comparisons {
		// New diagnostic section
		if fc.DiagnosticTitle != currentDiagnostic {
			if currentDiagnostic != "" {
				fmt.Fprintln(file, "")
			}
			currentDiagnostic = fc.DiagnosticTitle
			fmt.Fprintf(file, "### Diagnostic: %s\n\n", escapeMarkdown(currentDiagnostic))
			fmt.Fprintln(file, "| Field Path | Unified Value | Legacy Value |")
			fmt.Fprintln(file, "|------------|---------------|--------------|")

			// Write context fields first (if available)
			if context, exists := contextFields[currentDiagnostic]; exists {
				for _, ctxField := range context {
					matchIndicator := "✅"
					if !ctxField.Matched {
						matchIndicator = "❌"
					}
					fmt.Fprintf(file, "| %s %s | %s | %s |\n",
						matchIndicator,
						escapeMarkdown(ctxField.FieldPath),
						escapeMarkdown(ctxField.UnifiedValue),
						escapeMarkdown(ctxField.LegacyValue))
				}
			}
		}

		// Write field row
		fmt.Fprintf(file, "| %s | %s | %s |\n",
			escapeMarkdown(fc.FieldPath),
			escapeMarkdown(fc.UnifiedValue),
			escapeMarkdown(fc.LegacyValue))
	}

	fmt.Fprintln(file, "")
}

func writeMDSection(file *os.File, comparisons []FieldComparison) {
	currentDiagnostic := ""

	for _, fc := range comparisons {
		// New diagnostic section
		if fc.DiagnosticTitle != currentDiagnostic {
			if currentDiagnostic != "" {
				fmt.Fprintln(file, "")
			}
			currentDiagnostic = fc.DiagnosticTitle
			fmt.Fprintf(file, "### Diagnostic: %s\n\n", escapeMarkdown(currentDiagnostic))
			fmt.Fprintln(file, "| Field Path | Unified Value | Legacy Value |")
			fmt.Fprintln(file, "|------------|---------------|--------------|")
		}

		// Write field row
		fmt.Fprintf(file, "| %s | %s | %s |\n",
			escapeMarkdown(fc.FieldPath),
			escapeMarkdown(fc.UnifiedValue),
			escapeMarkdown(fc.LegacyValue))
	}

	fmt.Fprintln(file, "")
}

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"|", "\\|",
		"\n", " ",
		"\r", "",
	)
	return replacer.Replace(s)
}

// extractContextFieldsFromSingleDiagnostic extracts context fields from a diagnostic that exists only in one flow
//
//nolint:gocyclo // High complexity needed for extracting and formatting multiple context fields with conditional logic
func extractContextFieldsFromSingleDiagnostic(title string, diag types.Diagnostic, isUnified bool) []FieldComparison {
	var comparisons []FieldComparison

	// Extract Range
	comparisons = append(comparisons, FieldComparison{
		DiagnosticTitle: title,
		FieldPath:       "Range.Start",
		Matched:         false,
		UnifiedValue: func() string {
			if isUnified {
				return formatPosition(diag.Range.Start)
			} else {
				return "N/A"
			}
		}(),
		LegacyValue: func() string {
			if !isUnified {
				return formatPosition(diag.Range.Start)
			} else {
				return "N/A"
			}
		}(),
	})

	comparisons = append(comparisons, FieldComparison{
		DiagnosticTitle: title,
		FieldPath:       "Range.End",
		Matched:         false,
		UnifiedValue: func() string {
			if isUnified {
				return formatPosition(diag.Range.End)
			} else {
				return "N/A"
			}
		}(),
		LegacyValue: func() string {
			if !isUnified {
				return formatPosition(diag.Range.End)
			} else {
				return "N/A"
			}
		}(),
	})

	// Try to extract OssIssueData
	ossData, ok := diag.Data.AdditionalData.(types.OssIssueData)
	if !ok {
		// Try to convert from map
		ossData, ok = convertMapToOssIssueData(diag.Data.AdditionalData)
	}

	if ok {
		// Extract PackageName
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.PackageName",
			Matched:         false,
			UnifiedValue: func() string {
				if isUnified {
					return formatAny(ossData.PackageName)
				} else {
					return "N/A"
				}
			}(),
			LegacyValue: func() string {
				if !isUnified {
					return formatAny(ossData.PackageName)
				} else {
					return "N/A"
				}
			}(),
		})

		// Extract Version
		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.Version",
			Matched:         false,
			UnifiedValue: func() string {
				if isUnified {
					return formatAny(ossData.Version)
				} else {
					return "N/A"
				}
			}(),
			LegacyValue: func() string {
				if !isUnified {
					return formatAny(ossData.Version)
				} else {
					return "N/A"
				}
			}(),
		})

		// Extract Introducing Package (from[1])
		introducingPkg := ""
		if len(ossData.From) > 1 {
			introducingPkg = ossData.From[1]
		}

		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.From[1] (Introducing Package)",
			Matched:         false,
			UnifiedValue: func() string {
				if isUnified {
					return formatAny(introducingPkg)
				} else {
					return "N/A"
				}
			}(),
			LegacyValue: func() string {
				if !isUnified {
					return formatAny(introducingPkg)
				} else {
					return "N/A"
				}
			}(),
		})

		// Extract Introducing Package Name and Version
		introName, introVersion := parsePackageNameVersion(introducingPkg)

		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.From[1].Name (Introducing Package Name)",
			Matched:         false,
			UnifiedValue: func() string {
				if isUnified {
					return formatAny(introName)
				} else {
					return "N/A"
				}
			}(),
			LegacyValue: func() string {
				if !isUnified {
					return formatAny(introName)
				} else {
					return "N/A"
				}
			}(),
		})

		comparisons = append(comparisons, FieldComparison{
			DiagnosticTitle: title,
			FieldPath:       "Data.AdditionalData.From[1].Version (Introducing Package Version)",
			Matched:         false,
			UnifiedValue: func() string {
				if isUnified {
					return formatAny(introVersion)
				} else {
					return "N/A"
				}
			}(),
			LegacyValue: func() string {
				if !isUnified {
					return formatAny(introVersion)
				} else {
					return "N/A"
				}
			}(),
		})
	}

	return comparisons
}
