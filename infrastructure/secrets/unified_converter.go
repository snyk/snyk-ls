package secrets

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// convertTestResultToIssues converts a test result to a list of issues
func convertTestResultToIssues(ctx context.Context, testResult testapi.TestResult) ([]types.Issue, error) {
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
		title := trIssue.GetTitle()
		secretsIssueData, err := buildSecretsIssueData(ctx, trIssue)
		if err != nil {
			logger.Warn().Err(err).Msg("failed to build secrets issue data")
			continue
		}
		formattedMessage := buildFormattedMessage(title, trIssue.GetDescription(), trIssue.GetSeverity())
		ignoreDetails := getIgnoreDetailsFromTestResultIssue(trIssue)
		// TODO handle lesson URL (ticket exists).
		lessonURL := learn.Lesson{Url: "secrets-test"}

		issue := &snyk.Issue{
			ID:               secretsIssueData.Key,
			Message:          formattedMessage,
			FormattedMessage: formattedMessage,
			AffectedFilePath: affectedFilePath,
			ContentRoot:      workDir,
			IsNew:            false,
			IsIgnored:        ignoreDetails.Status == "accepted",
			Severity:         types.IssuesSeverity[strings.ToLower(trIssue.GetSeverity())],
			IgnoreDetails:    ignoreDetails,
			Product:          product.ProductSecrets,
			AdditionalData:   secretsIssueData,
			CWEs:             secretsIssueData.CWE,
			IssueType:        types.SecretsIssues,
			LessonUrl:        lessonURL.Url,
			Range:            computeRangeFromSourceLocations(trIssue.GetSourceLocations()),
		}

		// Calculate fingerprint
		fingerprint := utils.CalculateFingerprintFromAdditionalData(issue)
		issue.SetFingerPrint(fingerprint)
		issues = append(issues, issue)
	}
	return issues, nil
}

// buildFormattedMessage builds the comprehensive formatted message with all details
func buildFormattedMessage(title, description, severity string) string {
	var message strings.Builder
	// Title and description
	message.WriteString(fmt.Sprintf("## %s\n\n", title))
	message.WriteString(fmt.Sprintf("%s\n\n", description))
	// Severity
	message.WriteString(fmt.Sprintf("**Severity**: %s", severity))

	return message.String()
}

func buildSecretsIssueData(
	ctx context.Context,
	trIssue testapi.Issue,
) (snyk.SecretsIssueData, error) {
	logger := ctx2.LoggerFromContext(ctx).With().Str("method", "buildSecretsIssueData").Logger()
	logger.Debug().Interface("test api issue", trIssue.GetID()).Msg("building secrets issue data")

	slices.Sort(trIssue.GetCWEs())
	filePath := ctx2.FilePathFromContext(ctx)
	regs := computeRegionsFromSourceLocations(trIssue.GetSourceLocations())

	data := snyk.SecretsIssueData{
		Key:            trIssue.GetID(),
		Title:          trIssue.GetTitle(),
		Rule:           "name", // TODO check name exists in Problem json.RawMessage ??
		RuleId:         trIssue.GetID(),
		CWE:            trIssue.GetCWEs(),
		FilePath:       string(filePath),
		Regions:        regs,
		Markers:        make([]snyk.Marker, 0), // TODO convert markers from ??
		IsSecurityType: true,
		PriorityScore:  nil, // We will add risk score for Secrets in the future.
	}
	return data, nil
}

// Compute sarif.Regions from testapi.SourceLocations.
func computeRegionsFromSourceLocations(locs []testapi.SourceLocation) []sarif.Region {
	regs := make([]sarif.Region, 0)
	for _, loc := range locs {
		regs = append(regs, sarif.Region{
			StartLine:   loc.FromLine,
			EndLine:     *loc.ToLine,
			StartColumn: *loc.FromColumn,
			EndColumn:   *loc.ToColumn,
		})
	}
	return regs
}

// Compute types.Range from testapi.SourceLocations. Use first location as start and last location as end.
func computeRangeFromSourceLocations(locs []testapi.SourceLocation) types.Range {
	return types.Range{
		Start: types.Position{
			Line:      locs[0].FromLine,
			Character: *locs[0].FromColumn,
		},
		End: types.Position{
			Line:      *locs[len(locs)-1].ToLine,
			Character: *locs[len(locs)-1].ToColumn,
		},
	}
}

// Get ignore details from test result issue.
func getIgnoreDetailsFromTestResultIssue(trIssue testapi.Issue) *types.IgnoreDetails {
	trIgnoreDetails := trIssue.GetIgnoreDetails()
	trIgnoreDetailsName := trIgnoreDetails.GetIgnoredBy()
	trIgnoreDetailsStatus := trIgnoreDetails.GetStatus()
	return &types.IgnoreDetails{
		Category:   trIgnoreDetails.GetIgnoreReasonType(),
		Reason:     *trIgnoreDetails.GetJustification(),
		Expiration: trIgnoreDetails.GetExpiresAt().String(),
		IgnoredOn:  *trIgnoreDetails.GetCreatedAt(),
		IgnoredBy:  trIgnoreDetailsName.Name, // TODO check if use email instead ??
		Status:     sarif.SuppresionStatus(trIgnoreDetailsStatus),
	}
}
