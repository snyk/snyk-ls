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

package oss

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	"github.com/snyk/snyk-ls/internal/constants"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// WorkflowMetadata contains metadata from unified workflow execution
type WorkflowMetadata struct {
	ProjectName       string
	PackageManager    string
	DisplayTargetFile string
	DependencyCount   int
	OrgID             string
}

// ConvertFindingDataToIssues converts testapi.FindingData from unified workflow to types.Issue
// This is the main entry point for converting findings from the new unified test API to the
// language server's Issue format, maintaining compatibility with existing Issue consumers.
func ConvertFindingDataToIssues(
	ctx context.Context,
	findings []testapi.FindingData,
	workDir types.FilePath,
	path types.FilePath,
	logger *zerolog.Logger,
	errorReporter error_reporting.ErrorReporter,
	learnService learn.Service,
	packageIssueCache map[string][]types.Issue,
	format string,
	metadata *WorkflowMetadata,
) []types.Issue {
	if ctx.Err() != nil {
		return nil
	}

	if len(findings) == 0 {
		return []types.Issue{}
	}

	var issues []types.Issue
	duplicateCheckMap := map[string]bool{}

	for _, finding := range findings {
		// Skip if context is canceled
		if ctx.Err() != nil {
			break
		}

		issue, err := convertFindingToIssue(finding, workDir, path, learnService, format, metadata)

		if err != nil {
			findingIdStr := ""
			if finding.Id != nil {
				findingIdStr = finding.Id.String()
			}
			logger.Warn().Err(err).Str("findingId", findingIdStr).Msg("Failed to convert finding to issue")
			continue
		}

		// Generate duplicate check key
		vuln := extractSnykVulnProblem(finding)
		if vuln == nil {
			findingIdStr := ""
			if finding.Id != nil {
				findingIdStr = finding.Id.String()
			}
			logger.Warn().Str("findingId", findingIdStr).Msg("No vulnerability problem found in finding")
			continue
		}

		duplicateKey := fmt.Sprintf("%s|%s|%s", path, vuln.Id, vuln.PackageName)
		if duplicateCheckMap[duplicateKey] {
			continue
		}

		// Add to package cache
		packageKey := fmt.Sprintf("%s@%s", vuln.PackageName, vuln.PackageVersion)
		packageIssueCache[packageKey] = append(packageIssueCache[packageKey], issue)

		issues = append(issues, issue)
		duplicateCheckMap[duplicateKey] = true
	}

	return issues
}

// convertFindingToIssue converts a single testapi.FindingData to a snyk.Issue
func convertFindingToIssue(finding testapi.FindingData, workDir types.FilePath, affectedFilePath types.FilePath, learnService learn.Service, format string, metadata *WorkflowMetadata) (*snyk.Issue, error) {
	if finding.Attributes == nil {
		return nil, fmt.Errorf("finding has no attributes")
	}

	// Extract the primary vulnerability problem
	vuln := extractSnykVulnProblem(finding)
	if vuln == nil {
		return nil, fmt.Errorf("no vulnerability problem found in finding")
	}

	// Build OssIssueData from finding
	additionalData := buildOssIssueData(finding, vuln, affectedFilePath, metadata)

	// Extract severity
	severity := extractSeverity(finding)

	// Convert finding ID to string
	findingIdStr := ""
	if finding.Id != nil {
		findingIdStr = finding.Id.String()
	}

	// Convert ecosystem to string
	ecosystemStr := extractEcosystemString(vuln.Ecosystem)

	// Extract lesson URL from learn service
	lessonURL := ""
	if learnService != nil {
		lesson, err := learnService.GetLesson(ecosystemStr, vuln.Id, extractCWEs(finding), extractCVEs(finding), types.DependencyVulnerability)
		if err == nil && lesson != nil {
			lessonURL = lesson.Url
		}
	}

	// Build Issue
	issue := &snyk.Issue{
		ID:            vuln.Id,
		Severity:      severity,
		IssueType:     types.DependencyVulnerability,
		IsIgnored:     false, // TODO check if finding.Attributes.Suppression != nil is correct or how to get pending status
		IsNew:         false,
		IgnoreDetails: nil, // extractIgnoreDetails(finding), // TODO revisit when we have open source ignore policies added
		// TODO: The unified API doesn't provide file locations with line/column information
		// in the FindingData. Like the legacy converter, we need to:
		// 1. Read the manifest file content (package.json, pom.xml, etc.)
		// 2. Use RangeFinder (NpmRangeFinder, mavenRangeFinder, etc.) to parse and find the dependency declaration
		// 3. Extract the line/column range
		//
		// This file parsing should happen at the scanner level (similar to UnmarshallAndRetrieveAnalysis)
		// and be passed to the converter, or the converter should accept file content as a parameter.
		//
		// For now, returning empty range as the unified API doesn't expose this information directly.
		Range:               types.Range{}, // filled on the top level
		Message:             buildMessage(finding, additionalData, format),
		FormattedMessage:    buildFormattedMessage(finding, vuln, ecosystemStr),
		ContentRoot:         workDir,
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductOpenSource,
		References:          extractReferences(finding, vuln),
		IssueDescriptionURL: createIssueURL(vuln.Id),
		CodeActions:         []types.CodeAction{},  // Code actions generated by codeaction layer
		CodelensCommands:    []types.CommandData{}, // Codelens commands generated by codelens layer
		Ecosystem:           ecosystemStr,
		CWEs:                extractCWEs(finding),
		CVEs:                extractCVEs(finding),
		AdditionalData:      additionalData,
		LessonUrl:           lessonURL,
		FindingId:           findingIdStr,
	}

	// Calculate fingerprint
	fingerprint := utils.CalculateFingerprintFromAdditionalData(issue)
	issue.SetFingerPrint(fingerprint)

	return issue, nil
}

// buildOssIssueData constructs the OssIssueData from FindingData
func buildOssIssueData(
	finding testapi.FindingData,
	vuln *testapi.SnykVulnProblem,
	affectedFilePath types.FilePath,
	metadata *WorkflowMetadata,
) snyk.OssIssueData {
	attrs := finding.Attributes

	// Extract line number first (needed for key generation)
	lineNumber := extractLineNumber(finding)

	// Build key - use lineNumber for both start and end like legacy converter
	key := util.GetIssueKey(vuln.Id, string(affectedFilePath), lineNumber, lineNumber, 0, 0)

	ecosystemStr := extractEcosystemString(vuln.Ecosystem)

	// Extract lesson URL if learn service is available (note: passed via context, not directly here)
	lessonURL := ""

	data := snyk.OssIssueData{
		Key:                key,
		Title:              attrs.Title,
		Name:               vuln.PackageName,
		LineNumber:         lineNumber,
		Identifiers:        extractIdentifiers(finding),
		Description:        attrs.Description,
		References:         extractReferences(finding, vuln),
		Version:            extractVersion(finding, vuln),
		License:            extractLicense(finding),
		PackageManager:     ecosystemStr,
		PackageName:        vuln.PackageName,
		From:               extractDependencyPath(finding),
		FixedIn:            vuln.InitiallyFixedInVersions,
		UpgradePath:        buildUpgradePath(finding, vuln),
		IsUpgradable:       len(vuln.InitiallyFixedInVersions) > 0,
		CVSSv3:             extractCVSSv3(vuln),
		CvssScore:          float64(vuln.CvssBaseScore),
		CvssSources:        convertCvssSources(vuln),
		Exploit:            extractExploit(vuln),
		IsPatchable:        false, // Patches not supported in unified workflow yet
		ProjectName:        "",
		DisplayTargetFile:  affectedFilePath,
		Language:           extractLanguageFromEcosystem(vuln.Ecosystem),
		Details:            attrs.Description,
		MatchingIssues:     []snyk.OssIssueData{}, // Matching issues computed by delta processing
		Lesson:             lessonURL,             // Will be populated after issue creation
		Remediation:        buildRemediationAdvice(finding, vuln),
		AppliedPolicyRules: extractAppliedPolicyRules(finding),
	}

	// Set project name from metadata if available
	if metadata != nil {
		data.ProjectName = metadata.ProjectName
	}

	return data
}

// extractEcosystemString extracts the package manager string from the ecosystem structure
func extractEcosystemString(ecosystem testapi.SnykvulndbPackageEcosystem) string {
	// Try to get build package ecosystem (most common for OSS)
	buildEco, err := ecosystem.AsSnykvulndbBuildPackageEcosystem()
	if err == nil {
		return buildEco.PackageManager
	}

	// Fallback: try OS package ecosystem
	osEco, err := ecosystem.AsSnykvulndbOsPackageEcosystem()
	if err == nil {
		return string(osEco.Type)
	}

	// Fallback: return empty string
	return ""
}

// extractSnykVulnProblem finds the first SnykVuln problem in the finding
func extractSnykVulnProblem(finding testapi.FindingData) *testapi.SnykVulnProblem {
	if finding.Attributes == nil {
		return nil
	}

	for _, problem := range finding.Attributes.Problems {
		disc, err := problem.Discriminator()
		if err == nil && disc == "snyk_vuln" {
			vuln, err := problem.AsSnykVulnProblem()
			if err == nil {
				return &vuln
			}
		}
	}

	return nil
}

// extractSeverity extracts severity from finding rating
func extractSeverity(finding testapi.FindingData) types.Severity {
	if finding.Attributes == nil {
		return types.Low
	}

	severityStr := string(finding.Attributes.Rating.Severity)
	switch severityStr {
	case "critical":
		return types.Critical
	case "high":
		return types.High
	case "medium":
		return types.Medium
	case "low":
		return types.Low
	default:
		return types.Low
	}
}

// extractCWEs extracts CWE identifiers from problems
func extractCWEs(finding testapi.FindingData) []string {
	if finding.Attributes == nil {
		return nil
	}

	var cwes []string
	for _, problem := range finding.Attributes.Problems {
		disc, err := problem.Discriminator()
		if err == nil && disc == "cwe" {
			cwe, err := problem.AsCweProblem()
			if err == nil {
				cwes = append(cwes, cwe.Id)
			}
		}
	}

	return cwes
}

// extractCVEs extracts CVE identifiers from problems
func extractCVEs(finding testapi.FindingData) []string {
	if finding.Attributes == nil {
		return nil
	}

	var cves []string
	for _, problem := range finding.Attributes.Problems {
		disc, err := problem.Discriminator()
		if err == nil && disc == "cve" {
			cve, err := problem.AsCveProblem()
			if err == nil {
				cves = append(cves, cve.Id)
			}
		}
	}

	return cves
}

// extractIdentifiers builds the Identifiers struct from problems
func extractIdentifiers(finding testapi.FindingData) snyk.Identifiers {
	return snyk.Identifiers{
		CWE: extractCWEs(finding),
		CVE: extractCVEs(finding),
	}
}

// extractDependencyPath extracts the dependency path from evidence
func extractDependencyPath(finding testapi.FindingData) []string {
	if finding.Attributes == nil {
		return nil
	}

	for _, evidence := range finding.Attributes.Evidence {
		disc, err := evidence.Discriminator()
		// Try both "dependency_path" and "dependencypath" for compatibility
		if err == nil && disc == "dependency_path" {
			depPath, err := evidence.AsDependencyPathEvidence()
			if err == nil && depPath.Path != nil {
				// Convert []testapi.Package to []string
				var path []string
				for _, pkg := range depPath.Path {
					path = append(path, pkg.Name+"@"+pkg.Version)
				}
				return path
			}
		}
	}

	return []string{}
}

// buildUpgradePath builds the upgrade path from evidence and fixed versions
func buildUpgradePath(finding testapi.FindingData, vuln *testapi.SnykVulnProblem) []any {
	// Extract dependency path
	depPath := extractDependencyPath(finding)
	if len(depPath) == 0 || len(vuln.InitiallyFixedInVersions) == 0 {
		return []any{}
	}

	// Build upgrade path: first element is false (no patch),
	// then only the package that needs to be upgraded with its fixed version
	// Legacy format: [false, "package@fixedVersion"]
	pkgName := vuln.PackageName
	// TODO this needs to be updated once the upgrade path is correct and complete in the API
	fixedVersion := vuln.InitiallyFixedInVersions[0]
	upgradePath := []any{false, fmt.Sprintf("%s@%s", pkgName, fixedVersion)}

	return upgradePath
}

// extractReferences extracts references from finding and vulnerability problem
func extractReferences(finding testapi.FindingData, vuln *testapi.SnykVulnProblem) []types.Reference {
	references := []types.Reference{} // Initialize as empty slice, not nil

	// Extract references from vulnerability problem if available
	if vuln != nil && len(vuln.References) > 0 {
		for _, ref := range vuln.References {
			// Parse URL string to *url.URL
			parsedURL, err := url.Parse(ref.Url)
			if err != nil {
				continue
			}
			references = append(references, types.Reference{
				Title: ref.Title,
				Url:   parsedURL,
			})
		}
	}

	return references
}

// extractCVSSv3 extracts CVSS v3 string from vulnerability
func extractCVSSv3(vuln *testapi.SnykVulnProblem) string {
	// Find CVSS v3.1 from Snyk in sources
	for _, source := range vuln.CvssSources {
		if source.CvssVersion == "3.1" {
			return source.Vector
		}
	}

	return ""
}

// convertCvssSources converts CVSS sources to types.CvssSource
func convertCvssSources(vuln *testapi.SnykVulnProblem) []types.CvssSource {
	var sources []types.CvssSource
	for _, source := range vuln.CvssSources {
		sources = append(sources, types.CvssSource{
			Type:             string(source.Type),
			Vector:           source.Vector,
			Assigner:         source.Assigner,
			Severity:         string(source.Severity),
			BaseScore:        float64(source.BaseScore),
			CvssVersion:      source.CvssVersion,
			ModificationTime: source.ModifiedAt.Format("2006-01-02T15:04:05.000Z"),
		})
	}

	return sources
}

// extractExploit extracts exploit maturity information
func extractExploit(vuln *testapi.SnykVulnProblem) string {
	if len(vuln.ExploitDetails.MaturityLevels) == 0 {
		return ""
	}

	// Return the secondary maturity level (CVSSv3) to match legacy behavior
	// Legacy API used the CVSSv3 default exploit
	var exploitLevel string
	for _, level := range vuln.ExploitDetails.MaturityLevels {
		if level.Type == "secondary" {
			exploitLevel = level.Level
			break
		}
	}

	// Fallback to primary (CVSSv4) if no secondary found
	if exploitLevel == "" {
		for _, level := range vuln.ExploitDetails.MaturityLevels {
			if level.Type == "primary" {
				exploitLevel = level.Level
				break
			}
		}
	}

	// Fallback to first level if neither found
	if exploitLevel == "" {
		exploitLevel = vuln.ExploitDetails.MaturityLevels[0].Level
	}

	// Normalize case to match legacy format (title case for multi-word, unchanged for single word)
	if exploitLevel == "not defined" {
		return "Not Defined"
	}
	if exploitLevel == "proof of concept" {
		return "Proof of Concept"
	}
	if exploitLevel == "functional" {
		return "Functional"
	}
	if exploitLevel == "high" {
		return "High"
	}

	return exploitLevel
}

// extractLanguageFromEcosystem extracts language from ecosystem structure
func extractLanguageFromEcosystem(ecosystem testapi.SnykvulndbPackageEcosystem) string {
	// Try to get build package ecosystem (most common for OSS)
	buildEco, err := ecosystem.AsSnykvulndbBuildPackageEcosystem()
	if err == nil {
		return buildEco.Language
	}

	// Fallback: try OS package ecosystem
	osEco, err := ecosystem.AsSnykvulndbOsPackageEcosystem()
	if err == nil {
		// OS ecosystems don't have a language field, derive from type
		return string(osEco.Type)
	}

	// Fallback: return empty string
	return ""
}

// extractVersion extracts the package version from finding locations
func extractVersion(finding testapi.FindingData, vuln *testapi.SnykVulnProblem) string {
	if finding.Attributes == nil {
		return vuln.PackageVersion // Fallback to vuln's version
	}

	// Look for package location matching the vulnerable package
	for _, location := range finding.Attributes.Locations {
		disc, err := location.Discriminator()
		if err == nil && disc == "package" {
			pkgLoc, err := location.AsPackageLocation()
			if err == nil && pkgLoc.Package.Name == vuln.PackageName {
				return pkgLoc.Package.Version
			}
		}
	}

	// Fallback to package version from vuln
	return vuln.PackageVersion
}

// buildRemediationAdvice builds remediation advice text
func buildRemediationAdvice(finding testapi.FindingData, vuln *testapi.SnykVulnProblem) string {
	if len(vuln.InitiallyFixedInVersions) == 0 {
		return "No remediation available"
	}

	fixedVersion := vuln.InitiallyFixedInVersions[0]
	return fmt.Sprintf("Upgrade %s to version %s or higher", vuln.PackageName, fixedVersion)
}

// extractAppliedPolicyRules extracts policy modifications from finding attributes
func extractAppliedPolicyRules(finding testapi.FindingData) snyk.AppliedPolicyRules {
	// PolicyModifications structure extraction is complex and depends on the testapi schema
	// For now, return empty struct as policy rules are not critical for initial converter implementation
	// This can be enhanced once the actual PolicyModification structure is better understood
	return snyk.AppliedPolicyRules{}
}

// buildMessage builds the short message for the issue
func buildMessage(finding testapi.FindingData, data snyk.OssIssueData, format string) string {
	title := finding.Attributes.Title
	if format == config.FormatHtml {
		// HTML formatting handled elsewhere
		title = finding.Attributes.Title
	}

	message := fmt.Sprintf(
		"%s affecting package %s. %s",
		title,
		data.PackageName,
		data.Remediation,
	)

	const maxLength = 200
	if len(message) > maxLength {
		message = message[:maxLength] + "... (Snyk)"
	}

	return message
}

// buildFormattedMessage builds the comprehensive formatted message with all details
func buildFormattedMessage(finding testapi.FindingData, vuln *testapi.SnykVulnProblem, ecosystem string) string {
	if finding.Attributes == nil {
		return ""
	}

	attrs := finding.Attributes
	var message strings.Builder

	// Title and description
	message.WriteString(fmt.Sprintf("## %s\n\n", attrs.Title))
	message.WriteString(fmt.Sprintf("%s\n\n", attrs.Description))

	// Package information
	message.WriteString(fmt.Sprintf("**Package**: %s@%s\n", vuln.PackageName, vuln.PackageVersion))
	message.WriteString(fmt.Sprintf("**Ecosystem**: %s\n", ecosystem))

	// Severity and CVSS
	message.WriteString(fmt.Sprintf("**Severity**: %s", attrs.Rating.Severity))
	if vuln.CvssBaseScore > 0 {
		message.WriteString(fmt.Sprintf(" (CVSS Score: %.1f)\n", vuln.CvssBaseScore))
	} else {
		message.WriteString("\n")
	}

	// Fixed versions
	if len(vuln.InitiallyFixedInVersions) > 0 {
		message.WriteString(fmt.Sprintf("\n**Fixed in**: %s\n", strings.Join(vuln.InitiallyFixedInVersions, ", ")))
	}

	// Exploit maturity
	if len(vuln.ExploitDetails.MaturityLevels) > 0 {
		message.WriteString(fmt.Sprintf("**Exploit Maturity**: %s\n", vuln.ExploitDetails.MaturityLevels[0].Type))
	}

	return message.String()
}

// extractLineNumber extracts line number from finding locations
func extractLineNumber(finding testapi.FindingData) int {
	// TODO: Same as extractRange - the unified API doesn't provide line numbers directly.
	// The legacy converter gets this by parsing the manifest file to find where the dependency is declared.
	// Until the unified converter has access to file content and uses RangeFinder,
	// we default to 0 (which matches the legacy behavior when file content is unavailable).
	return 0
}

// extractLicense extracts license information from finding problems
func extractLicense(finding testapi.FindingData) string {
	if finding.Attributes == nil {
		return ""
	}

	// Look for license problems in the problems array
	for _, problem := range finding.Attributes.Problems {
		disc, err := problem.Discriminator()
		if err == nil && disc == "snyk_license" {
			licenseProblem, err := problem.AsSnykLicenseProblem()
			if err == nil {
				return licenseProblem.License
			}
		}
	}

	return ""
}

// createIssueURL creates the Snyk issue description URL
func createIssueURL(id string) *url.URL {
	u, err := url.Parse(fmt.Sprintf("%s/%s", constants.SNYK_VULN_DB_BASE_URL, id))
	if err != nil {
		return nil
	}

	return u
}
