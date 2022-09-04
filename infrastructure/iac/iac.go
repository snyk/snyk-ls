package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gomarkdown/markdown"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
)

var (
	issueSeverities = map[string]snyk.Severity{
		"high": snyk.High,
		"low":  snyk.Low,
	}
)

var extensions = map[string]bool{
	".yaml": true,
	".yml":  true,
	".json": true,
	".tf":   true,
}

type Scanner struct {
	instrumentor  performance.Instrumentor
	errorReporter error_reporting.ErrorReporter
	analytics     ux2.Analytics
	cli           cli.Executor
	mutex         sync.Mutex
}

func New(instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, analytics ux2.Analytics, cli cli.Executor) *Scanner {
	return &Scanner{
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		analytics:     analytics,
		cli:           cli,
		mutex:         sync.Mutex{},
	}
}

func (iac *Scanner) IsEnabled() bool {
	return config.CurrentConfig().IsSnykIacEnabled()
}

func (iac *Scanner) Product() snyk.Product {
	return snyk.ProductInfrastructureAsCode
}

func (iac *Scanner) SupportedCommands() []snyk.CommandName {
	return []snyk.CommandName{}
}

func (iac *Scanner) Scan(ctx context.Context, path string, _ string) (issues []snyk.Issue) {
	if ctx.Err() != nil {
		log.Debug().Msg("Cancelling IAC scan - IAC scanner received cancellation signal")
		return make([]snyk.Issue, 0)
	}

	documentURI := uri.PathToUri(path) // todo get rid of lsp dep
	if !iac.isSupported(documentURI) {
		return
	}
	p := progress.NewTracker(false)
	p.BeginUnquantifiableLength("Scanning for Snyk IaC issues", path)
	defer p.End("Snyk Iac Scan completed.")

	var workspacePath string
	if uri.IsDirectory(documentURI) {
		workspacePath = uri.PathFromUri(documentURI)
	} else {
		workspacePath = filepath.Dir(uri.PathFromUri(documentURI))
	}

	scanResults, err := iac.doScan(ctx, documentURI, workspacePath)
	p.Report(80)
	if err != nil {
		if err != context.Canceled {
			iac.errorReporter.CaptureError(err)
		}
	}
	if len(scanResults) > 0 {
		for _, s := range scanResults {
			issues = append(issues, iac.retrieveAnalysis(s, workspacePath)...)
		}
	}
	iac.trackResult(err == nil)
	return issues
}

func (iac *Scanner) isSupported(documentURI sglsp.DocumentURI) bool {
	ext := filepath.Ext(uri.PathFromUri(documentURI))
	return uri.IsDirectory(documentURI) || extensions[ext]
}

func (iac *Scanner) doScan(ctx context.Context, documentURI sglsp.DocumentURI, workspacePath string) (scanResults []iacScanResult, err error) {
	method := "iac.doScan"
	s := iac.instrumentor.StartSpan(ctx, method)
	defer iac.instrumentor.Finish(s)

	iac.mutex.Lock()
	defer iac.mutex.Unlock()

	cmd := iac.cliCmd(documentURI)
	res, err := iac.cli.Execute(ctx, cmd, workspacePath)

	if err != nil {
		switch errorType := err.(type) {
		case *exec.ExitError:
			if errorType.ExitCode() > 1 {
				errorOutput := string(res) + "\n\n\nSTDERR output:\n" + string(err.(*exec.ExitError).Stderr)
				if strings.Contains(errorOutput, "Could not find any valid IaC files") ||
					strings.Contains(errorOutput, "CustomError: Not a recognised option did you mean --file") {
					return scanResults, nil
				}
				log.Err(err).Str("method", method).Str("output", errorOutput).Msg("Error while calling Snyk CLI")
				err = errors.Wrap(err, fmt.Sprintf("Snyk CLI error executing %v. Output: %s", cmd, errorOutput))
				return nil, err
			}
		default:
			log.Err(err).Str("method", method).Msg("Error while calling Snyk CLI")
			return nil, err
		}
	}

	output := string(res)
	if strings.HasPrefix(output, "[") {
		if err = json.Unmarshal(res, &scanResults); err != nil {
			err = errors.Wrap(err, fmt.Sprintf("Cannot unmarshall %s", output))
			log.Err(err).Str("method", method).Msg("Cannot unmarshall")
			return nil, err
		}
	} else {
		var scanResult iacScanResult
		if err = json.Unmarshal(res, &scanResult); err != nil {
			err = errors.Wrap(err, fmt.Sprintf("Cannot unmarshall %s", output))
			log.Err(err).Str("method", method).Msg("Cannot unmarshall")
			return nil, err
		}
		scanResults = append(scanResults, scanResult)
	}
	return scanResults, nil
}

func (iac *Scanner) cliCmd(u sglsp.DocumentURI) []string {
	path, err := filepath.Abs(uri.PathFromUri(u))
	if err != nil {
		log.Err(err).Str("method", "iac.Scan").
			Msg("Error while extracting file absolutePath")
	}
	cmd := iac.cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliSettings().Path(), "iac", "test", path, "--json"})
	log.Debug().Msg(fmt.Sprintf("IAC: command: %s", cmd))
	return cmd
}

func (iac *Scanner) retrieveAnalysis(scanResult iacScanResult, workspacePath string) []snyk.Issue {
	targetFile := filepath.Join(workspacePath, scanResult.TargetFile)
	rawFileContent, err := os.ReadFile(targetFile)
	fileContentString := ""
	if err != nil {
		errorMessage := "Could not read file content from " + targetFile
		log.Err(err).Msg(errorMessage)
		iac.errorReporter.CaptureError(errors.Wrap(err, errorMessage))
	} else {
		fileContentString = string(rawFileContent)
	}

	log.Debug().Msgf("found %v IAC issues for file %s", len(scanResult.IacIssues), targetFile)
	var issues []snyk.Issue

	for _, issue := range scanResult.IacIssues {
		if issue.LineNumber > 0 {
			issue.LineNumber -= 1
		} else {
			issue.LineNumber = 0
		}

		issues = append(issues, iac.toIssue(targetFile, issue, fileContentString))
	}
	return issues
}

func (iac *Scanner) trackResult(success bool) {
	var result ux2.Result
	if success {
		result = ux2.Success
	} else {
		result = ux2.Error
	}
	iac.analytics.AnalysisIsReady(ux2.AnalysisIsReadyProperties{
		AnalysisType: ux2.InfrastructureAsCode,
		Result:       result,
	})
}

// todo this needs to be pushed up to presentation
func (iac *Scanner) getExtendedMessage(issue iacIssue) string {
	title := issue.Title
	description := issue.IacDescription.Issue
	impact := issue.IacDescription.Impact
	resolve := issue.IacDescription.Resolve

	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
		description = string(markdown.ToHTML([]byte(description), nil, nil))
		impact = string(markdown.ToHTML([]byte(impact), nil, nil))
		resolve = string(markdown.ToHTML([]byte(resolve), nil, nil))
	}

	return fmt.Sprintf("\n### %s: %s\n\n**Issue:** %s\n\n**Impact:** %s\n\n**Resolve:** %s\n",
		issue.PublicID, title, description, impact, resolve)

}

func (iac *Scanner) toIssue(affectedFilePath string, issue iacIssue, fileContent string) snyk.Issue {
	const defaultRangeStart = 0
	const defaultRangeEnd = 80
	title := issue.IacDescription.Issue
	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
	}
	codeActionTitle := fmt.Sprintf("Open description of '%s' in browser (Snyk)", issue.Title)
	issueURL := iac.createIssueURL(issue.PublicID)

	// Try to gather the length of the line for the range
	rangeStart := defaultRangeStart
	rangeEnd := defaultRangeEnd
	if fileContent != "" {
		lines := strings.Split(strings.ReplaceAll(fileContent, "\r\n", "\n"), "\n")
		if len(lines) > (issue.LineNumber) {
			line := lines[issue.LineNumber]
			lineLength := len(line)
			trimmedLineLength := len(strings.TrimLeft(line, " "))
			leadingSpacesCount := lineLength - trimmedLineLength
			rangeStart = leadingSpacesCount
			rangeEnd = lineLength
		}
	}

	return snyk.Issue{
		ID: issue.PublicID,
		Range: snyk.Range{
			Start: snyk.Position{Line: issue.LineNumber, Character: rangeStart},
			End:   snyk.Position{Line: issue.LineNumber, Character: rangeEnd},
		},
		Message:             fmt.Sprintf("%s (Snyk)", title),
		FormattedMessage:    iac.getExtendedMessage(issue),
		Severity:            iac.toIssueSeverity(issue.Severity),
		AffectedFilePath:    affectedFilePath,
		Product:             snyk.ProductInfrastructureAsCode,
		IssueDescriptionURL: issueURL,
		IssueType:           snyk.InfrastructureIssue,
		CodeActions: []snyk.CodeAction{{
			Title:       codeActionTitle,
			IsPreferred: false,
			Command: snyk.Command{
				Title:     codeActionTitle,
				Command:   snyk.OpenBrowserCommand,
				Arguments: []interface{}{issueURL.String()},
			},
		}},
	}
}

func (iac *Scanner) createIssueURL(id string) *url.URL {
	parse, err := url.Parse("https://snyk.io/security-rules/" + id)
	if err != nil {
		iac.errorReporter.CaptureError(errors.Wrap(err, "unable to create issue link for iac issue "+id))
	}
	return parse
}

func (iac *Scanner) toIssueSeverity(snykSeverity string) snyk.Severity {
	severity, ok := issueSeverities[snykSeverity]
	if !ok {
		return snyk.Medium
	}
	return severity
}
