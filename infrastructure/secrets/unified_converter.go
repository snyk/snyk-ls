package secrets

import (
	"context"
	"fmt"
	"strings"

	codeClient "github.com/snyk/code-client-go/sarif"
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
		secretsIssueData, err := buildSecretsIssueData(ctx, trIssue, affectedFilePath)
		if err != nil {
			logger.Warn().Err(err).Msg("failed to build oss issue data")
			continue
		}
		formattedMessage := buildFormattedMessage(title, trIssue.GetDescription(), trIssue.GetSeverity())

		isIgnored := false
		suppressionDetails := trIssue.GetSuppression()
		isIgnored = suppressionDetails != nil && suppressionDetails.Status == testapi.SuppressionStatusIgnored
		ignoreDetails := types.IgnoreDetails{
			Reason:     *suppressionDetails.Justification,
			Expiration: suppressionDetails.ExpiresAt.String(),
			IgnoredOn:  *suppressionDetails.CreatedAt,
			Status:     codeClient.SuppresionStatus(suppressionDetails.Status),
		}

		// TODO handle lesson URL (ticket exists)
		lessonURL := learn.Lesson{Url: "secrets-test"}

		issue := &snyk.Issue{
			ID:               secretsIssueData.Key,
			Message:          formattedMessage,
			FormattedMessage: formattedMessage,
			AffectedFilePath: affectedFilePath,
			ContentRoot:      workDir,
			IsNew:            false,
			IsIgnored:        isIgnored,
			Severity:         types.IssuesSeverity[strings.ToLower(trIssue.GetSeverity())],
			IgnoreDetails:    &ignoreDetails,
			Product:          product.ProductSecrets,
			AdditionalData:   secretsIssueData,
			CWEs:             secretsIssueData.CWE,
			IssueType:        types.SecretsIssues,
			LessonUrl:        lessonURL.Url,
			// TODO check handle in infrastructure/secrets/converter.go:computeMultipleDiagnostics
			//Range: trIssue.GetSourceLocations(),
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
	affectedFilePath types.FilePath,
) (*snyk.SecretsIssueData, error) {
	// TODO add mapping
	return nil, nil
}
