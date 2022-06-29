package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/cli"
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
}

func New(instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, analytics ux2.Analytics, cli cli.Executor) *Scanner {
	return &Scanner{
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		analytics:     analytics,
		cli:           cli,
	}
}

func (iac *Scanner) IsEnabled() bool {
	return config.CurrentConfig().IsSnykIacEnabled()
}

func (iac *Scanner) Scan(ctx context.Context, path string, output snyk.ScanResultProcessor, _ string, _ []string) {
	documentURI := uri.PathToUri(path) //todo get rid of lsp dep
	p := progress.NewTracker(false)
	p.Begin("Scanning for Snyk IaC issues", path)
	defer p.End("Snyk Iac Scan completed.")

	if !iac.isSupported(documentURI) {
		return
	}
	scanResults, err := iac.doScan(ctx, documentURI)
	p.Report(80)
	if err != nil {
		iac.errorReporter.CaptureError(err)
	}
	if len(scanResults) > 0 {
		iac.retrieveAnalysis(scanResults[0], output)
	}
	iac.trackResult(err == nil)
	p.End("Snyk Iac Scan completed.")
}

func (iac *Scanner) isSupported(documentURI sglsp.DocumentURI) bool {
	ext := filepath.Ext(uri.PathFromUri(documentURI))
	return extensions[ext]
}

func (iac *Scanner) doScan(ctx context.Context, documentURI sglsp.DocumentURI) (scanResults []iacScanResult, err error) {
	method := "iac.doScan"
	s := iac.instrumentor.StartSpan(ctx, method)
	defer iac.instrumentor.Finish(s)

	defer log.Debug().Str("method", method).Msg("done.")
	log.Debug().Str("method", method).Msg("started.")

	var workspaceUri string
	if !isDirectory(documentURI) {
		workspaceUri = filepath.Dir(uri.PathFromUri(documentURI))
	} else {
		workspaceUri = uri.PathFromUri(documentURI)
	}

	res, err := iac.cli.Execute(iac.cliCmd(documentURI), workspaceUri)
	if err != nil {
		switch err := err.(type) {
		case *exec.ExitError:
			if err.ExitCode() > 1 {
				errorOutput := string(res)
				if strings.Contains(errorOutput, "Could not find any valid IaC files") ||
					strings.Contains(errorOutput, "CustomError: Not a recognised option did you mean --file") {
					return scanResults, nil
				}
				log.Err(err).Str("method", method).Str("output", errorOutput).Msg("Error while calling Snyk CLI")
				return nil, fmt.Errorf("%v: %v", err, errorOutput)
			}
		default:
			log.Err(err).Str("method", method).Msg("Error while calling Snyk CLI")
			return nil, err
		}
	}

	if isDirectory(documentURI) {
		if err := json.Unmarshal(res, &scanResults); err != nil {
			return nil, err
		}
	} else {
		var scanResult iacScanResult
		if err := json.Unmarshal(res, &scanResult); err != nil {
			return nil, err
		}
		scanResults = append(scanResults, scanResult)
	}
	return scanResults, nil
}

func isDirectory(documentURI sglsp.DocumentURI) bool {
	workspaceUri := uri.PathFromUri(documentURI)
	stat, err := os.Stat(workspaceUri)
	if err != nil {
		log.Err(err).Err(err).Msg("Error while checking file")
		return false
	}
	return stat.IsDir()
}

func (iac *Scanner) cliCmd(u sglsp.DocumentURI) []string {
	path, err := filepath.Abs(uri.PathFromUri(u))
	if err != nil {
		log.Err(err).Str("method", "iac.Scan").
			Msg("Error while extracting file absolutePath")
	}
	cmd := iac.cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliPath(), "iac", "test", path, "--json"})
	log.Debug().Msg(fmt.Sprintf("IAC: command: %s", cmd))
	return cmd
}

func (iac *Scanner) retrieveAnalysis(scanResult iacScanResult, output snyk.ScanResultProcessor) {
	issues := iac.convertScanResult(scanResult)

	if len(issues) > 0 {
		output(issues)
	}
}

func (iac *Scanner) convertScanResult(res iacScanResult) []snyk.Issue {
	var issues []snyk.Issue

	for _, issue := range res.IacIssues {
		if issue.LineNumber > 0 {
			issue.LineNumber -= 1
		} else {
			issue.LineNumber = 0
		}

		issues = append(issues, iac.toIssue(res.TargetFile, issue))
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

//todo this needs to be pushed up to presentation
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

func (iac *Scanner) toIssue(affectedFilePath string, issue iacIssue) snyk.Issue {
	title := issue.Title
	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
	}

	return snyk.Issue{
		ID: issue.PublicID,
		Range: snyk.Range{
			Start: snyk.Position{Line: issue.LineNumber, Character: 0},
			End:   snyk.Position{Line: issue.LineNumber, Character: 80},
		},
		Message:          fmt.Sprintf("%s (Snyk)", title),
		LegacyMessage:    iac.getExtendedMessage(issue),
		Severity:         iac.toIssueSeverity(issue.Severity),
		AffectedFilePath: affectedFilePath,
	}
}

func (iac *Scanner) toIssueSeverity(snykSeverity string) snyk.Severity {
	severity, ok := issueSeverities[snykSeverity]
	if !ok {
		return snyk.Medium
	}
	return severity
}
