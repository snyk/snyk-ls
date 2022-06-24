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

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace/deleteme"
	"github.com/snyk/snyk-ls/domain/snyk/issues"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	lspSeverities = map[string]sglsp.DiagnosticSeverity{
		"high": sglsp.Error,
		"low":  sglsp.Warning,
	}
	issueSeverities = map[string]issues.Severity{
		"high": issues.High,
		"low":  issues.Low,
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
	analytics     ux.Analytics
	cli           cli.Executor
}

func New(instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, analytics ux.Analytics, cli cli.Executor) *Scanner {
	return &Scanner{
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		analytics:     analytics,
		cli:           cli,
	}
}

func (iac *Scanner) IsSupported(documentURI sglsp.DocumentURI) bool {
	ext := filepath.Ext(uri.PathFromUri(documentURI))
	return extensions[ext]
}

func (iac *Scanner) ScanWorkspace(ctx context.Context, documentURI sglsp.DocumentURI, output deleteme.ResultProcessor) {
	p := progress.NewTracker(false)
	p.Begin(fmt.Sprintf("Scanning for Snyk IaC issues in %s", documentURI), "Scanning Workspace.")
	defer p.End("Snyk Iac Scan completed.")

	scanResults, err := iac.doScan(ctx, documentURI)
	if err != nil {
		iac.errorReporter.CaptureError(err)
	}
	for _, scanResult := range scanResults {
		u := uri.PathToUri(filepath.Join(uri.PathFromUri(documentURI), scanResult.TargetFile))
		iac.retrieveAnalysis(u, scanResult, output)
	}
	iac.trackResult(err == nil)
}

func (iac *Scanner) ScanFile(ctx context.Context, documentURI sglsp.DocumentURI, output deleteme.ResultProcessor) {
	p := progress.NewTracker(false)
	p.Begin(fmt.Sprintf("Scanning for Snyk IaC issues in %s", documentURI), "Scanning single file.")
	defer p.End("Snyk Iac Scan completed.")

	if !iac.IsSupported(documentURI) {
		return
	}
	scanResults, err := iac.doScan(ctx, documentURI)
	p.Report(80)
	if err != nil {
		iac.errorReporter.CaptureError(err)
	}
	if len(scanResults) > 0 {
		iac.retrieveAnalysis(documentURI, scanResults[0], output)
	}
	iac.trackResult(err == nil)
	p.End("Snyk Iac Scan completed.")
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
		log.Err(err).Str("method", "iac.ScanFile").
			Msg("Error while extracting file absolutePath")
	}
	cmd := iac.cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliPath(), "iac", "test", path, "--json"})
	log.Debug().Msg(fmt.Sprintf("IAC: command: %s", cmd))
	return cmd
}

func (iac *Scanner) retrieveAnalysis(documentURI sglsp.DocumentURI, scanResult iacScanResult, output deleteme.ResultProcessor) {
	diagnostics, hoverDetails := iac.convertScanResult(scanResult)

	if len(diagnostics) > 0 {
		output(diagnostics, []hover.DocumentHovers{{Uri: documentURI, Hover: hoverDetails}})
	}
}

func (iac *Scanner) convertScanResult(res iacScanResult) ([]lsp.Diagnostic, []hover.Hover[hover.Context]) {
	var diagnostics []lsp.Diagnostic
	var hoverDetails []hover.Hover[hover.Context]

	for _, issue := range res.IacIssues {
		if issue.LineNumber > 0 {
			issue.LineNumber -= 1
		} else {
			issue.LineNumber = 0
		}

		diagnostics = append(diagnostics, iac.toDiagnostic(issue))
		hoverDetails = append(hoverDetails, iac.toHover(issue))
	}

	return diagnostics, hoverDetails
}

func (iac *Scanner) trackResult(success bool) {
	var result ux.Result
	if success {
		result = ux.Success
	} else {
		result = ux.Error
	}
	iac.analytics.AnalysisIsReady(ux.AnalysisIsReadyProperties{
		AnalysisType: ux.InfrastructureAsCode,
		Result:       result,
	})
}

func (iac *Scanner) toHover(issue iacIssue) hover.Hover[hover.Context] {
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

	return hover.Hover[hover.Context]{
		Id: issue.PublicID,
		Range: sglsp.Range{
			Start: sglsp.Position{Line: issue.LineNumber, Character: 0},
			End:   sglsp.Position{Line: issue.LineNumber, Character: 80},
		},
		Message: fmt.Sprintf("\n### %s: %s\n\n**Issue:** %s\n\n**Impact:** %s\n\n**Resolve:** %s\n",
			issue.PublicID, title, description, impact, resolve),
		Context: issues.Issue{
			ID:        issue.PublicID,
			Severity:  iac.toIssueSeverity(issue.Severity),
			IssueType: issues.InfrastructureIssue,
		},
	}
}

func (iac *Scanner) toDiagnostic(issue iacIssue) lsp.Diagnostic {
	title := issue.Title
	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
	}

	diagnostic := lsp.Diagnostic{
		Source: "Snyk LS",
		Range: sglsp.Range{
			Start: sglsp.Position{Line: issue.LineNumber, Character: 0},
			End:   sglsp.Position{Line: issue.LineNumber, Character: 80},
		},
		Message:  fmt.Sprintf("%s (Snyk)", title),
		Severity: iac.lspSeverity(issue.Severity),
		Code:     issue.PublicID,
	}
	return diagnostic
}

func (iac *Scanner) lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := lspSeverities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}
func (iac *Scanner) toIssueSeverity(snykSeverity string) issues.Severity {
	severity, ok := issueSeverities[snykSeverity]
	if !ok {
		return issues.Medium
	}
	return severity
}
