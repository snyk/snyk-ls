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
	"os"
	"slices"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/float"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// convertTestResultToIssues converts a test result to a list of issues
func convertTestResultToIssues(ctx context.Context, testResult testapi.TestResult, packageIssueCache map[string][]types.Issue) ([]types.Issue, error) {
	logger := ctx2.LoggerFromContext(ctx).With().
		Str("method", "convertTestResultToIssues").
		Str("testID", testResult.GetTestID().String()).Logger()

	issuesFromTestResult, err := testapi.NewIssuesFromTestResult(ctx, testResult)
	if err != nil {
		return nil, fmt.Errorf("couldn't create issues from test result: %w", err)
	}

	subject, err := testResult.GetTestSubject().AsDepGraphSubject()
	if err != nil {
		msg := "failed to fetch test subject"
		logger.Error().Err(err).Msg(msg)
		return nil, fmt.Errorf(msg+": %w", err)
	}

	workDir := ctx2.WorkDirFromContext(ctx)
	filePath := ctx2.FilePathFromContext(ctx)

	displayTargetFile := subject.Locator.Paths[0]
	logger.Debug().Str("displayTargetFile", displayTargetFile).Msg("displayTargetFile")
	affectedFilePath := getAbsTargetFilePath(&logger, string(workDir), displayTargetFile, workDir, filePath)

	issues := []types.Issue{}
	for _, trIssue := range issuesFromTestResult {
		ecoData, found := trIssue.GetData(testapi.DataKeyTechnology)
		if !found {
			logger.Warn().Msg("failed to get ecosystem")
			continue
		}
		ecosystemStr, ok := ecoData.(string)
		if !ok {
			logger.Warn().Msg("failed to get ecosystem")
			continue
		}

		problem, err := getProblem(trIssue)
		if err != nil {
			return nil, fmt.Errorf("failed to get and convert primary problem: %w", err)
		}

		introducingFinding, err := getIntroducingFinding(trIssue, problem)
		if err != nil {
			logger.Warn().Err(err).Msg("failed to get introducing finding")
			continue
		}
		dependencyPath := extractDependencyPath(introducingFinding)
		myRange, err := getRange(ctx, string(affectedFilePath), ecosystemStr, dependencyPath)
		if err != nil {
			logger.Warn().Err(err).Msg("failed to get range")
		}

		title := trIssue.GetTitle()
		ossIssueData, err := buildOssIssueData(ctx, trIssue, problem, introducingFinding, affectedFilePath, myRange, ecosystemStr)
		if err != nil {
			logger.Warn().Err(err).Msg("failed to build oss issue data")
			continue
		}

		// populate matching issues, we include the first primary finding
		ossIssueData.MatchingIssues = []snyk.OssIssueData{}
		for _, finding := range trIssue.GetFindings() {
			issueData, err := buildOssIssueData(ctx, trIssue, problem, finding, affectedFilePath, myRange, ecosystemStr)
			if err != nil {
				logger.Warn().Err(err).Msg("failed to build oss issue data")
				continue
			}
			ossIssueData.MatchingIssues = append(ossIssueData.MatchingIssues, issueData)
		}

		remediationAdvice := getRemediationAdvice(ossIssueData)
		//ignoreDetails := trIssue.GetIgnoreDetails()
		//isIgnored := ignoreDetails != nil && ignoreDetails.GetStatus() == testapi.SuppressionStatusIgnored
		message := buildMessage(title, problem.PackageName, remediationAdvice)
		formattedMessage := buildFormattedMessage(problem, ecosystemStr, title, trIssue.GetDescription(), trIssue.GetSeverity())
		references := extractReferences(problem)
		issueDescriptionURL := createIssueURL(problem.Id)
		lessonURL := Lesson(ctx, problem, ossIssueData.Identifiers.CWE, ossIssueData.Identifiers.CVE, ecosystemStr)

		issue := &snyk.Issue{
			ID:                  trIssue.GetID(),
			Severity:            types.IssuesSeverity[strings.ToLower(trIssue.GetSeverity())],
			IssueType:           types.DependencyVulnerability,
			IsIgnored:           false,
			IsNew:               false,
			Range:               myRange,
			Message:             message,
			FormattedMessage:    formattedMessage,
			ContentRoot:         workDir,
			AffectedFilePath:    affectedFilePath,
			Product:             product.ProductOpenSource,
			References:          references,
			IssueDescriptionURL: issueDescriptionURL,
			CodeActions:         nil,
			CodelensCommands:    nil,
			Ecosystem:           ecosystemStr,
			CWEs:                ossIssueData.Identifiers.CWE,
			CVEs:                ossIssueData.Identifiers.CVE,
			AdditionalData:      ossIssueData,
			LessonUrl:           lessonURL,
			FindingId:           introducingFinding.Id.String(),
		}

		// Calculate fingerprint
		fingerprint := utils.CalculateFingerprintFromAdditionalData(issue)
		issue.SetFingerPrint(fingerprint)
		issues = append(issues, issue)
	}
	return issues, nil
}

func getIntroducingFinding(issue testapi.Issue, problem *testapi.SnykVulnProblem) (*testapi.FindingData, error) {
	findings := issue.GetFindings()
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings found in issue")
	}

	// we want to find the finding, that is a direct dependency and introduces the problem
	for _, finding := range findings {
		dependencyPath := extractDependencyPath(finding)
		if len(dependencyPath) > 1 {
			findingPackageName := strings.Split(dependencyPath[1], "@")[0]
			if findingPackageName == problem.PackageName {
				return finding, nil
			}
		}
	}
	// no findings found that are direct dependencies, we just take the first now
	return findings[0], nil
}

func getProblem(issue testapi.Issue) (*testapi.SnykVulnProblem, error) {
	problem, err := issue.GetPrimaryProblem().AsSnykVulnProblem()
	if err != nil {
		return nil, fmt.Errorf("failed to get and convert primary problem: %w", err)
	}
	return &problem, nil
}

func getRange(ctx context.Context, affectedFilePath, packageManager string, dependencyPath []string) (types.Range, error) {
	logger := ctx2.LoggerFromContext(ctx).With().Str("method", "getRangeFromRangeFinder").Logger()
	content, err := os.ReadFile(affectedFilePath)
	if err != nil {
		logger.Error().Err(err).Msg("failed to read file")
		return types.Range{}, err
	}

	node := getDependencyNode(&logger, types.FilePath(affectedFilePath), packageManager, dependencyPath, content)
	if node == nil {
		logger.Error().Msg("failed to get dependency node")
		return types.Range{}, fmt.Errorf("failed to get dependency node")
	}

	r := types.Range{
		Start: types.Position{
			Line:      node.Line,
			Character: node.StartChar,
		},
		End: types.Position{
			Line:      node.Line,
			Character: node.EndChar,
		},
	}
	return r, nil
}

// buildMessage builds the short message for the issue
func buildMessage(title, packageName, remediation string) string {
	message := fmt.Sprintf(
		"%s affecting package %s. %s",
		title,
		packageName,
		remediation,
	)

	const maxLength = 200
	if len(message) > maxLength {
		message = message[:maxLength] + "... (Snyk)"
	}

	return message
}

// buildRemediationAdvice builds remediation advice text from the upgrade path
// Matches legacy flow: uses UpgradePath[1] (the package to be upgraded)
// Logic matches Legacy's GetRemediation() which checks IsUpgradable || IsPatchable
func buildRemediationAdvice(finding *testapi.FindingData, problem *testapi.SnykVulnProblem, ecosystemStr string) string {
	// Get the upgrade path from the API
	upgradePath := buildUpgradePath(finding, problem)
	dependencyPath := extractDependencyPath(finding)

	// Extract the actual version from the finding
	actualVersion := extractVersion(finding, problem)

	// Build upgrade message
	upgradeMessage := ""
	if len(upgradePath) > 1 {
		packageToUpgrade, ok := upgradePath[1].(string)
		if ok {
			upgradeMessage = fmt.Sprintf("Upgrade to %s", packageToUpgrade)
		}
	}

	// Check if this is an "outdated dependency" scenario
	// isOutdated: UpgradePath[1] == From[1] means the direct dependency should already have the fix
	// but the lockfile is out of date
	isOutdated := upgradeMessage != "" &&
		len(upgradePath) > 1 &&
		len(dependencyPath) > 1 &&
		upgradePath[1] == dependencyPath[1]

	// Match Legacy logic: check IsUpgradable
	// IsUpgradable = len(vuln.InitiallyFixedInVersions) > 0
	// Note: IsPatchable is always false in unified workflow (patches not supported)
	isUpgradable := len(problem.InitiallyFixedInVersions) > 0

	// If we have an upgrade message (either from upgradable status or fix relationships), provide remediation
	if upgradeMessage != "" || isUpgradable {
		if isOutdated {
			// Outdated dependencies scenario - return outdated message
			return buildOutdatedDependencyMessage(problem.PackageName, actualVersion, ecosystemStr)
		}
		// Return upgrade message when available
		// Note: if isUpgradable but upgradeMessage is empty, we return empty string
		// but that case should be rare since upgradePath is built from InitiallyFixedInVersions
		return upgradeMessage
	}

	// No remediation available
	return "No remediation advice available"
}

func extractDependencyPath(finding *testapi.FindingData) []string {
	if finding.Attributes == nil {
		return nil
	}

	for _, evidence := range finding.Attributes.Evidence {
		disc, err := evidence.Discriminator()
		// Try both "dependency_path"
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

// extractUpgradePackage extracts upgrade path information from finding.Relationships.Fix
func extractUpgradePackage(finding *testapi.FindingData) []string {
	// Check if finding has relationships and fix data
	if finding.Relationships == nil || finding.Relationships.Fix == nil {
		return nil
	}

	fixData := finding.Relationships.Fix.Data
	if fixData == nil || fixData.Attributes == nil {
		return nil
	}

	// Get the action from fix attributes
	action := fixData.Attributes.Action
	if action == nil {
		return nil
	}

	// Check if this is an upgrade_package_advice action
	disc, err := action.Discriminator()
	if err != nil || disc != "upgrade_package_advice" {
		return nil
	}

	// Extract the upgrade package advice
	upgradeAction, err := action.AsUpgradePackageAdvice()
	if err != nil {
		return nil
	}

	// Get the first upgrade path (if available)
	if len(upgradeAction.UpgradePaths) == 0 {
		return nil
	}

	upgradePath := upgradeAction.UpgradePaths[0]
	if len(upgradePath.DependencyPath) == 0 {
		return nil
	}

	// Convert []testapi.Package to []string
	var path []string
	for _, pkg := range upgradePath.DependencyPath {
		path = append(path, pkg.Name+"@"+pkg.Version)
	}
	return path
}

// buildUpgradePath builds the upgrade path from the unified API fix data
// Returns: [false, "intermediate1@version", "intermediate2@version", ..., "target@version"]
// This matches Legacy CLI behavior which shows the full dependency path with upgraded versions
func buildUpgradePath(finding *testapi.FindingData, vuln *testapi.SnykVulnProblem) []any {
	// Get the dependency path (From field)
	dependencyPath := extractDependencyPath(finding)
	if len(dependencyPath) == 0 {
		// Fallback when no dependency path is available
		if len(vuln.InitiallyFixedInVersions) > 0 {
			result := []any{false}
			result = append(result, fmt.Sprintf("%s@%s", vuln.PackageName, vuln.InitiallyFixedInVersions[0]))
			return result
		}
		return []any{}
	}

	// Extract upgrade path from the unified API
	upgradePath := extractUpgradePackage(finding)

	// Build result matching Legacy format: [false, intermediate1@v1, intermediate2@v2, ..., target@version]
	result := []any{false} // First element is always false (no patch)

	// If we have upgrade path data from the API, use it
	if len(upgradePath) > 1 {
		// Add all packages from upgrade path except the root (skip index 0)
		for i := 1; i < len(upgradePath); i++ {
			result = append(result, upgradePath[i])
		}
	} else if len(vuln.InitiallyFixedInVersions) > 0 {
		// Fallback: Use dependency path with upgraded version for target
		// Replace last package with upgraded version
		for i := 1; i < len(dependencyPath)-1; i++ {
			result = append(result, dependencyPath[i])
		}
		result = append(result, fmt.Sprintf("%s@%s", vuln.PackageName, vuln.InitiallyFixedInVersions[0]))
	}

	return result
}

// buildOssIssueData constructs the OssIssueData from FindingData
func buildOssIssueData(
	ctx context.Context,
	trIssue testapi.Issue,
	problem *testapi.SnykVulnProblem,
	finding *testapi.FindingData,
	affectedFilePath types.FilePath,
	issueRange types.Range,
	ecosystem string,
) (snyk.OssIssueData, error) {
	logger := ctx2.LoggerFromContext(ctx).With().Str("method", "buildOssIssueData").Logger()
	logger.Debug().Interface("problem", problem.Id).Interface("finding", finding.Id).Msg("building oss issue data")

	attrs := finding.Attributes

	// Build key - use lineNumber for both start and end like legacy converter
	key := util.GetIssueKey(
		problem.Id,
		string(affectedFilePath),
		issueRange.Start.Line,
		issueRange.End.Line,
		issueRange.Start.Character,
		issueRange.End.Character,
	)

	// Extract project name from dependency path (from[0])
	dependencyPath := extractDependencyPath(finding)
	projectName := ""
	if len(dependencyPath) > 0 {
		// from[0] is "projectName@version", extract just the name
		parts := strings.Split(dependencyPath[0], "@")
		projectName = parts[0]
	}

	slices.Sort(trIssue.GetCWEs())
	slices.Sort(trIssue.GetCVEs())

	data := snyk.OssIssueData{
		Key:        key,
		Title:      attrs.Title,
		Name:       problem.PackageName,
		LineNumber: issueRange.Start.Line,
		Identifiers: snyk.Identifiers{
			CWE: trIssue.GetCWEs(),
			CVE: trIssue.GetCVEs(),
		},
		Description:        attrs.Description,
		References:         extractReferences(problem),
		Version:            extractVersion(finding, problem),
		License:            extractLicense(finding),
		PackageManager:     ecosystem,
		PackageName:        problem.PackageName,
		From:               extractDependencyPath(finding),
		FixedIn:            problem.InitiallyFixedInVersions,
		UpgradePath:        buildUpgradePath(finding, problem),
		IsUpgradable:       len(problem.InitiallyFixedInVersions) > 0,
		CVSSv3:             extractCVSSv3(problem),
		CvssScore:          float64(problem.CvssBaseScore),
		CvssSources:        convertCvssSources(problem),
		Exploit:            extractExploit(problem),
		IsPatchable:        false, // Patches not supported in unified workflow yet
		ProjectName:        projectName,
		DisplayTargetFile:  affectedFilePath,
		Language:           extractLanguageFromEcosystem(problem.Ecosystem),
		Details:            attrs.Description,
		MatchingIssues:     []snyk.OssIssueData{}, // populated in caller
		Lesson:             "",
		Remediation:        buildRemediationAdvice(finding, problem, ecosystem),
		AppliedPolicyRules: extractAppliedPolicyRules(),
		RiskScore:          trIssue.GetRiskScore(),
	}

	return data, nil
}

// extractReferences extracts references from finding and vulnerability problem
func extractReferences(problem *testapi.SnykVulnProblem) []types.Reference {
	references := []types.Reference{} // Initialize as empty slice, not nil

	// Extract references from vulnerability problem if available
	if problem != nil && len(problem.References) > 0 {
		for _, ref := range problem.References {
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
			BaseScore:        float.ToFixed(float64(source.BaseScore), 1),
			CvssVersion:      source.CvssVersion,
			ModificationTime: source.ModifiedAt.Format("2006-01-02T15:04:05.000000Z"),
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
func extractVersion(finding *testapi.FindingData, vuln *testapi.SnykVulnProblem) string {
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

// buildOutdatedDependencyMessage returns the message for outdated dependencies
// Matches legacy flow behavior
func buildOutdatedDependencyMessage(packageName, packageVersion, packageManager string) string {
	remediationAdvice := fmt.Sprintf("Your dependencies are out of date, "+
		"otherwise you would be using a newer %s than %s@%s. ", packageName, packageName, packageVersion)

	if packageManager == "npm" || packageManager == "yarn" || packageManager == "yarn-workspace" {
		remediationAdvice += "Try relocking your lockfile or deleting node_modules and reinstalling" +
			" your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	} else {
		remediationAdvice += "Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	}
	return remediationAdvice
}

// extractAppliedPolicyRules extracts policy modifications from finding attributes
func extractAppliedPolicyRules() snyk.AppliedPolicyRules {
	// PolicyModifications structure extraction is complex and depends on the testapi schema
	// For now, return empty struct as policy rules are not critical for initial converter implementation
	// This can be enhanced once the actual PolicyModification structure is better understood
	return snyk.AppliedPolicyRules{}
}

// buildFormattedMessage builds the comprehensive formatted message with all details
func buildFormattedMessage(problem *testapi.SnykVulnProblem, ecosystem, title, description, severity string) string {
	var message strings.Builder

	// Title and description
	message.WriteString(fmt.Sprintf("## %s\n\n", title))
	message.WriteString(fmt.Sprintf("%s\n\n", description))

	// Package information
	message.WriteString(fmt.Sprintf("**Package**: %s@%s\n", problem.PackageName, problem.PackageVersion))
	message.WriteString(fmt.Sprintf("**Ecosystem**: %s\n", ecosystem))

	// Severity and CVSS
	message.WriteString(fmt.Sprintf("**Severity**: %s", severity))
	if problem.CvssBaseScore > 0 {
		message.WriteString(fmt.Sprintf(" (CVSS Score: %.1f)\n", problem.CvssBaseScore))
	} else {
		message.WriteString("\n")
	}

	// Fixed versions
	if len(problem.InitiallyFixedInVersions) > 0 {
		message.WriteString(fmt.Sprintf("\n**Fixed in**: %s\n", strings.Join(problem.InitiallyFixedInVersions, ", ")))
	}

	// Exploit maturity
	maturityLevels := problem.ExploitDetails.MaturityLevels
	if len(maturityLevels) > 0 {
		for _, level := range maturityLevels {
			message.WriteString(fmt.Sprintf("\n**Exploit Maturity**: %s\n", level.Type))
		}
	}

	return message.String()
}

// extractLicense extracts license information from finding problems
func extractLicense(finding *testapi.FindingData) string {
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
	u, err := url.Parse(fmt.Sprintf("https://snyk.io/vuln/%s", id))
	if err != nil {
		return nil
	}

	return u
}

func Lesson(ctx context.Context, problem *testapi.SnykVulnProblem, cwes []string, cves []string, ecosystemStr string) string {
	var lessonURL string
	deps, depsFound := ctx2.DependenciesFromContext(ctx)
	if depsFound {
		if ls, ok := deps[ctx2.DepLearnService].(learn.Service); ok {
			// Extract lesson URL from learn service
			if ls != nil {
				lesson, err := ls.GetLesson(ecosystemStr, problem.Id, cwes, cves, types.DependencyVulnerability)
				if err == nil && lesson != nil {
					lessonURL = lesson.Url
				}
			}
		}
	}
	return lessonURL
}
