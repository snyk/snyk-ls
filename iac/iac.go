package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/gomarkdown/markdown"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	severities = map[string]sglsp.DiagnosticSeverity{
		"high": sglsp.Error,
		"low":  sglsp.Warning,
	}
	logger = environment.Logger
)

var extensions = map[string]bool{
	".yaml": true,
	".yml":  true,
	".json": true,
	".tf":   true,
}

func IsSupported(documentURI sglsp.DocumentURI) bool {
	ext := filepath.Ext(uri.PathFromUri(documentURI))
	return extensions[ext]
}

func ScanWorkspace(
	ctx context.Context,
	Cli cli.Executor,
	documentURI sglsp.DocumentURI,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	defer wg.Done()
	logger.WithField("method", "iac.ScanWorkspace").Debug(ctx, "started")
	defer logger.WithField("method", "iac.ScanWorkspace").Debug(ctx, "done")

	res, err := Cli.Execute(ctx, cliCmd(ctx, documentURI))
	if err != nil {
		switch err := err.(type) {
		case *exec.ExitError:
			if err.ExitCode() > 1 {
				logger.
					WithField("method", "iac.ScanWorkspace").
					WithField("output", string(res)).
					WithError(err).
					Error(ctx, "error while calling cli")
				reportErrorViaChan(documentURI, dChan, err)
				return
			}
			logger.
				WithField("method", "iac.ScanWorkspace").
				WithError(err).
				Warn(ctx, "exit code 1 while calling cli")
		default:
			reportErrorViaChan(documentURI, dChan, err)
			return
		}
	}

	var scanResults []iacScanResult
	if err := json.Unmarshal(res, &scanResults); err != nil {
		logger.
			WithField("method", "iac.ScanWorkspace").
			WithError(err).
			Error(ctx, "couldn't unmarshall")
		reportErrorViaChan(documentURI, dChan, err)
		return
	}

	logger.
		WithField("method", "iac.ScanWorkspace").
		Debug(ctx, "got diagnostics, now sending to channel")
	for _, scanResult := range scanResults {
		u := uri.PathToUri(filepath.Join(uri.PathFromUri(documentURI), scanResult.TargetFile))
		retrieveAnalysis(ctx, u, scanResult, dChan, hoverChan)
	}
}

func reportErrorViaChan(uri sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, err error) {
	dChan <- lsp.DiagnosticResult{
		Uri: uri,
		Err: err,
	}
}

func ScanFile(
	ctx context.Context,
	Cli cli.Executor,
	documentURI sglsp.DocumentURI,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	defer wg.Done()
	logger.WithField("method", "iac.ScanFile").Debug(ctx, "started")
	defer logger.WithField("method", "iac.ScanFile").Debug(ctx, "done")

	if !IsSupported(documentURI) {
		return
	}

	res, err := Cli.Execute(ctx, cliCmd(ctx, documentURI))
	if err != nil {
		switch err := err.(type) {
		case *exec.ExitError:
			if err.ExitCode() > 1 {
				logger.
					WithField("method", "iac.ScanFile").
					WithField("output", string(res)).
					WithError(err).
					Error(ctx, "error while calling cli")
				reportErrorViaChan(documentURI, dChan, err)
				return
			}
			logger.
				WithField("method", "iac.ScanFile").
				WithError(err).
				Warn(ctx, "exit code 1 while calling cli")
		default:
			reportErrorViaChan(documentURI, dChan, err)
			return
		}
	}

	var scanResults iacScanResult
	if err := json.Unmarshal(res, &scanResults); err != nil {
		logger.
			WithField("method", "iac.ScanFile").
			WithError(err).
			Error(ctx, "couldn't unmarshall")
		reportErrorViaChan(documentURI, dChan, err)
		return
	}

	logger.
		WithField("method", "iac.ScanWorkspace").
		WithField("iacScanResult", scanResults).
		Debug(ctx, "got it all unmarshalled, general!")

	retrieveAnalysis(ctx, documentURI, scanResults, dChan, hoverChan)
}

func cliCmd(ctx context.Context, u sglsp.DocumentURI) []string {
	path, err := filepath.Abs(uri.PathFromUri(u))
	if err != nil {
		logger.
			WithField("method", "cliCmd").
			WithError(err).
			Error(ctx, "couldn't determine absolute path")
	}
	cmd := cli.ExpandParametersFromConfig(
		ctx,
		[]string{environment.CliPath(), "iac", "test", path, "--json"},
	)

	logger.
		WithField("method", "cliCmd").
		WithField("cmd", cmd).
		Debug(ctx, "CLI IaC command")
	return cmd
}

func retrieveAnalysis(
	ctx context.Context,
	uri sglsp.DocumentURI,
	scanResult iacScanResult,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	diagnostics, hoverDetails := convertDiagnostics(scanResult)

	if len(diagnostics) > 0 {
		select {
		case dChan <- lsp.DiagnosticResult{Uri: uri, Diagnostics: diagnostics}:
			hoverChan <- lsp.Hover{Uri: uri, Hover: hoverDetails}

			logger.
				WithField("method", "iac.retrieveAnalysis").
				WithField("diagnosticCount", len(diagnostics)).
				Debug(ctx, "found diagnostics")
		default:
			logger.
				WithField("method", "iac.retrieveAnalysis").
				WithField("diagnosticCount", len(diagnostics)).
				Debug(ctx, "no diagnostics sent")
		}
	}
}

func convertDiagnostics(res iacScanResult) ([]lsp.Diagnostic, []lsp.HoverDetails) {
	var diagnostics []lsp.Diagnostic
	var hoverDetails []lsp.HoverDetails

	for _, issue := range res.IacIssues {
		title := issue.Title
		description := issue.IacDescription.Issue
		impact := issue.IacDescription.Impact
		resolve := issue.IacDescription.Resolve

		diagsRange := sglsp.Range{
			Start: sglsp.Position{Line: issue.LineNumber - 1, Character: 0},
			End:   sglsp.Position{Line: issue.LineNumber - 1, Character: 80},
		}

		if environment.Format == environment.FormatHtml {
			title = string(markdown.ToHTML([]byte(title), nil, nil))
			description = string(markdown.ToHTML([]byte(description), nil, nil))
			impact = string(markdown.ToHTML([]byte(impact), nil, nil))
			resolve = string(markdown.ToHTML([]byte(resolve), nil, nil))
		}

		diagnostic := lsp.Diagnostic{
			Source:   "Snyk LS",
			Range:    diagsRange,
			Message:  fmt.Sprintf("%s: %s\n\n", issue.PublicID, title),
			Severity: lspSeverity(issue.Severity),
			Code:     issue.PublicID,
		}

		diagnostics = append(diagnostics, diagnostic)

		hover := lsp.HoverDetails{
			Id:    issue.PublicID,
			Range: diagsRange,
			Message: fmt.Sprintf("\n### %s: %s\n\n**Issue:** %s\n\n**Impact:** %s\n\n**Resolve:** %s\n",
				issue.PublicID, title, description, impact, resolve),
		}
		hoverDetails = append(hoverDetails, hover)
	}

	return diagnostics, hoverDetails
}

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}
