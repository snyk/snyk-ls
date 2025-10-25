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
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/data_structure"
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

type ProblemsMap map[*testapi.SnykVulnProblem][]testapi.FindingData

// convertTestResultToIssues converts testapi.FindingData from unified workflow to types.Issue
// This is the main entry point for converting findings from the new unified test API to the
// language server's Issue format, maintaining compatibility with existing Issue consumers.
func convertTestResultToIssues(ctx context.Context, testResult testapi.TestResult, packageIssueCache map[string][]types.Issue) ([]types.Issue, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	logger := getLogger(ctx).With().Str("method", "convertTestResultToIssues").Logger()

	findings, complete, err := testResult.Findings(ctx)
	if err != nil {
		msg := "failed to fetch findings"
		logger.Error().Err(err).Msg(msg)
		return nil, fmt.Errorf(msg+": %w", err)
	}

	if !complete {
		const msg = "findings are not complete"
		logger.Error().Msg(msg)
		return nil, errors.New(msg)
	}

	if len(findings) == 0 {
		return []types.Issue{}, nil
	}

	// analyze test subject

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

	// Group findings by problem
	problems := asProblemsMap(ctx, findings)

	// Create issues from problems
	var issues []types.Issue
	for problem, problemFindings := range problems {
		issue, err := convertProblemToIssue(ctx, problem, problemFindings, affectedFilePath)
		if err != nil {
			logger.Err(err).Msg("Failed to convert finding to issue")
			return []types.Issue{}, err
		}

		// the resulting issue is a top level issue with matching issues that refer to that problem in the
		// field `matchingIssues`
		issues = append(issues, issue)

		// Add to package cache
		packageKey := fmt.Sprintf("%s@%s", problem.PackageName, problem.PackageVersion)
		packageIssueCache[packageKey] = append(packageIssueCache[packageKey], issue)
	}
	return issues, nil
}

func asProblemsMap(ctx context.Context, findings []testapi.FindingData) ProblemsMap {
	problems := ProblemsMap{}

	getKey := func(finding testapi.FindingData) *testapi.SnykVulnProblem {
		problem := extractSnykVulnProblem(finding)
		return problem
	}

	for _, finding := range findings {
		// Skip if context is canceled
		if ctx.Err() != nil {
			break
		}

		key := getKey(finding)
		if problems[key] == nil {
			problems[key] = []testapi.FindingData{}
		}

		problems[key] = append(problems[key], finding)
	}
	return problems
}

// convertProblemToIssue converts a single testapi.FindingData to a snyk.Issue
func convertProblemToIssue(ctx context.Context, problem *testapi.SnykVulnProblem, problemFindings []testapi.FindingData, affectedFilePath types.FilePath) (*snyk.Issue, error) {
	// Extract the primary vulnerability problem
	if problem == nil || problemFindings == nil {
		return nil, fmt.Errorf("no vulnerability problem found in problem")
	}

	c := Config(ctx)
	if c == nil {
		return nil, fmt.Errorf("no dependency config found in context")
	}
	logger := getLogger(ctx).With().Str("method", "convertProblemToIssue").Logger()
	workDir := ctx2.WorkDirFromContext(ctx)
	ecosystemStr := extractEcosystemString(problem.Ecosystem)

	// get the dependency path from the first finding
	dependencyPath := extractDependencyPath(problemFindings[0])

	myRange, err := getRange(ctx, string(affectedFilePath), ecosystemStr, dependencyPath)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to get range")
	}

	cwes, cves, titles, remediations, descriptions, ossIssues := findingsDataUsedInIssue(ctx, problem, problemFindings, affectedFilePath, myRange)
	title, remediation, description, cwes, cves, err := consolidate(cwes, cves, titles, remediations, descriptions, logger)
	if err != nil {
		return nil, err
	}

	lessonURL := Lesson(ctx, problem, cwes, cves, ecosystemStr)
	severity := types.IssuesSeverity[strings.ToLower(string(problem.Severity))]

	// let's use the first finding as the primary issue and the rest as matching issues
	additionalData := ossIssues[0]
	additionalData.MatchingIssues = ossIssues[1:]

	// Build Issue
	issue := &snyk.Issue{
		ID:                  problem.Id,
		Severity:            severity,
		IssueType:           types.DependencyVulnerability,
		IsIgnored:           false, // TODO check if problem.Attributes.Suppression != nil is correct or how to get pending status
		IsNew:               false,
		IgnoreDetails:       nil,     // extractIgnoreDetails(problem), // TODO revisit when we have open source ignore policies added
		Range:               myRange, // filled on the top level
		Message:             buildMessage(title, problem.PackageName, remediation),
		FormattedMessage:    buildFormattedMessage(problem, ecosystemStr, title, description, severity.String()),
		ContentRoot:         workDir,
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductOpenSource,
		References:          extractReferences(problem),
		IssueDescriptionURL: createIssueURL(problem.Id),
		CodeActions:         []types.CodeAction{},  // Code actions generated by code action layer
		CodelensCommands:    []types.CommandData{}, // Codelens commands generated by codelens layer
		Ecosystem:           ecosystemStr,
		CWEs:                cwes,
		CVEs:                cves,
		AdditionalData:      additionalData,
		LessonUrl:           lessonURL,
	}

	// Calculate fingerprint
	fingerprint := utils.CalculateFingerprintFromAdditionalData(issue)
	issue.SetFingerPrint(fingerprint)

	return issue, nil
}

func consolidate(cwes []string, cves []string, titles []string, remediations []string, descriptions []string, logger zerolog.Logger) (string, string, string, []string, []string, error) {
	cwes = data_structure.Unique(cwes)
	cves = data_structure.Unique(cves)
	titles = data_structure.Unique(titles)
	remediations = data_structure.Unique(remediations)
	descriptions = data_structure.Unique(descriptions)

	title, err := consolidateSlice("title", titles, logger)
	if err != nil {
		return "", "", "", nil, nil, err
	}

	remediation, err := consolidateSlice("remediation", remediations, logger)
	if err != nil {
		return "", "", "", nil, nil, err
	}

	description, err := consolidateSlice("description", descriptions, logger)
	if err != nil {
		return "", "", "", nil, nil, err
	}
	return title, remediation, description, cwes, cves, nil
}

func consolidateSlice(fieldName string, slice []string, logger zerolog.Logger) (string, error) {
	if len(slice) > 1 {
		logger.Warn().Any("slice", slice).Msgf("Multiple entries found for vulnerability, taking %s", slice[0])
	} else if len(slice) == 0 {
		msg := fmt.Sprintf("No %s found for vulnerability", fieldName)
		logger.Warn().Msg(msg)
		return "", fmt.Errorf("%s", msg)
	}
	value := slice[0]
	return value, nil
}

func findingsDataUsedInIssue(ctx context.Context, problem *testapi.SnykVulnProblem, problemFindings []testapi.FindingData, affectedFilePath types.FilePath, myRange types.Range) ([]string, []string, []string, []string, []string, []snyk.OssIssueData) {
	logger := getLogger(ctx).With().Str("method", "findingsDataUsedInIssue").Logger()
	var cwes, cves, titles, remediations, descriptions []string
	var ossIssues []snyk.OssIssueData
	for _, finding := range problemFindings {
		additionalData, err := buildOssIssueData(ctx, problem, finding, affectedFilePath, myRange)
		if err != nil {
			logger.Err(err).Msg("Failed to convert finding to issue")
			continue
		}
		ossIssues = append(ossIssues, additionalData)

		// ------------------------------------------------------
		// - collect finding data that needs to be consolidated -
		// ------------------------------------------------------

		cwes = append(cwes, extractCWEs(finding)...)
		cves = append(cves, extractCVEs(finding)...)
		titles = append(titles, additionalData.Title)
		remediations = append(remediations, additionalData.Remediation)
		descriptions = append(descriptions, additionalData.Description)
	}
	return cwes, cves, titles, remediations, descriptions, ossIssues
}

func Config(ctx context.Context) *config.Config {
	deps, found := ctx2.DependenciesFromContext(ctx)
	if !found {
		return nil
	}

	configDep := deps[ctx2.DepConfig]
	if configDep == nil {
		return nil
	}
	c, ok := configDep.(*config.Config)
	if !ok {
		return nil
	}
	return c
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

// buildOssIssueData constructs the OssIssueData from FindingData
func buildOssIssueData(ctx context.Context, problem *testapi.SnykVulnProblem, finding testapi.FindingData, affectedFilePath types.FilePath, myRange types.Range) (snyk.OssIssueData, error) {
	logger := getLogger(ctx).With().Str("method", "buildOssIssueData").Logger()
	logger.Debug().Interface("problem", problem).Interface("finding", finding.Id).Msg("building oss issue data")

	attrs := finding.Attributes

	// Build key - use lineNumber for both start and end like legacy converter
	key := util.GetIssueKey(
		problem.Id,
		string(affectedFilePath),
		myRange.Start.Line,
		myRange.End.Line,
		myRange.Start.Character,
		myRange.End.Character,
	)

	ecosystemStr := extractEcosystemString(problem.Ecosystem)

	data := snyk.OssIssueData{
		Key:                key,
		Title:              attrs.Title,
		Name:               problem.PackageName,
		LineNumber:         myRange.Start.Line,
		Identifiers:        extractIdentifiers(finding),
		Description:        attrs.Description,
		References:         extractReferences(problem),
		Version:            extractVersion(finding, problem),
		License:            extractLicense(finding),
		PackageManager:     ecosystemStr,
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
		ProjectName:        "",    //TODO
		DisplayTargetFile:  affectedFilePath,
		Language:           extractLanguageFromEcosystem(problem.Ecosystem),
		Details:            attrs.Description,
		MatchingIssues:     []snyk.OssIssueData{}, // populated in caller
		Lesson:             "",
		Remediation:        buildRemediationAdvice(problem),
		AppliedPolicyRules: extractAppliedPolicyRules(),
	}

	return data, nil
}

func getRange(ctx context.Context, affectedFilePath, packageManager string, dependencyPath []string) (types.Range, error) {
	logger := getLogger(ctx).With().Str("method", "getRangeFromRangeFinder").Logger()
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

func getLogger(ctx context.Context) *zerolog.Logger {
	logger := ctx2.LoggerFromContext(ctx)
	if logger == nil {
		l := zerolog.Nop()
		logger = &l
	}
	return logger
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
func buildRemediationAdvice(vuln *testapi.SnykVulnProblem) string {
	if len(vuln.InitiallyFixedInVersions) == 0 {
		return "No remediation available"
	}

	fixedVersion := vuln.InitiallyFixedInVersions[0]
	return fmt.Sprintf("Upgrade %s to version %s or higher", vuln.PackageName, fixedVersion)
}

// extractAppliedPolicyRules extracts policy modifications from finding attributes
func extractAppliedPolicyRules() snyk.AppliedPolicyRules {
	// PolicyModifications structure extraction is complex and depends on the testapi schema
	// For now, return empty struct as policy rules are not critical for initial converter implementation
	// This can be enhanced once the actual PolicyModification structure is better understood
	return snyk.AppliedPolicyRules{}
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
	u, err := url.Parse(fmt.Sprintf("https://snyk.io/vuln/%s", id))
	if err != nil {
		return nil
	}

	return u
}
