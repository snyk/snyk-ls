package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gomarkdown/markdown"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	severities = map[string]sglsp.DiagnosticSeverity{
		"high": sglsp.Error,
		"low":  sglsp.Warning,
	}
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

func ScanWorkspace(ctx context.Context, Cli cli.Executor, documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	defer wg.Done()
	scanResults, err := doScan(ctx, Cli, documentURI)
	if err != nil {
		reportErrorViaChan(documentURI, dChan, err)
	}
	for _, scanResult := range scanResults {
		u := uri.PathToUri(filepath.Join(uri.PathFromUri(documentURI), scanResult.TargetFile))
		retrieveAnalysis(u, scanResult, dChan, hoverChan)
	}
	trackResult(err == nil)
}

func ScanFile(ctx context.Context, Cli cli.Executor, documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	defer wg.Done()
	if !IsSupported(documentURI) {
		return
	}
	scanResults, err := doScan(ctx, Cli, documentURI)
	if err != nil {
		reportErrorViaChan(documentURI, dChan, err)
	}
	if len(scanResults) > 0 {
		retrieveAnalysis(documentURI, scanResults[0], dChan, hoverChan)
	}
	trackResult(err == nil)
}

func doScan(ctx context.Context, Cli cli.Executor, documentURI sglsp.DocumentURI) (scanResults []iacScanResult, err error) {
	method := "iac.doScan"
	s := di.Instrumentor().StartSpan(ctx, method)
	defer di.Instrumentor().Finish(s)

	defer log.Debug().Str("method", method).Msg("done.")
	log.Debug().Str("method", method).Msg("started.")

	var workspaceUri string
	if !isDirectory(documentURI) {
		workspaceUri = filepath.Dir(uri.PathFromUri(documentURI))
	} else {
		workspaceUri = uri.PathFromUri(documentURI)
	}
	res, err := Cli.Execute(cliCmd(documentURI), workspaceUri)
	if err != nil {
		switch err := err.(type) {
		case *exec.ExitError:
			log.Warn().Err(err).Str("method", method).Msg("Error while calling Snyk CLI")
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
			log.Warn().Err(err).Str("method", method).Msg("Error while calling Snyk CLI")
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

func reportErrorViaChan(uri sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, err error) {
	dChan <- lsp.DiagnosticResult{
		Uri: uri,
		Err: err,
	}
}

func cliCmd(u sglsp.DocumentURI) []string {
	path, err := filepath.Abs(uri.PathFromUri(u))
	if err != nil {
		log.Err(err).Str("method", "iac.ScanFile").
			Msg("Error while extracting file absolutePath")
	}
	cmd := cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliPath(), "iac", "test", path, "--json"})
	log.Debug().Msg(fmt.Sprintf("IAC: command: %s", cmd))
	return cmd
}

func retrieveAnalysis(
	uri sglsp.DocumentURI,
	scanResult iacScanResult,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	diagnostics, hoverDetails := convertDiagnostics(scanResult)

	if len(diagnostics) > 0 {
		select {
		case dChan <- lsp.DiagnosticResult{
			Uri:         uri,
			Diagnostics: diagnostics,
		}:
			hoverChan <- lsp.Hover{
				Uri:   uri,
				Hover: hoverDetails,
			}

			log.Debug().Str("method", "iac.retrieveAnalysis").Interface("diagnosticCount", len(diagnostics)).Msg("found sth")
		default:
			log.Debug().Str("method", "iac.retrieveAnalysis").Msg("no diags found & sent.")
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

		if issue.LineNumber > 0 {
			issue.LineNumber -= 1
		} else {
			issue.LineNumber = 0
		}

		diagsRange := sglsp.Range{
			Start: sglsp.Position{Line: issue.LineNumber, Character: 0},
			End:   sglsp.Position{Line: issue.LineNumber, Character: 80},
		}

		if config.CurrentConfig().Format() == config.FormatHtml {
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

func trackResult(success bool) {
	var result ux.Result
	if success {
		result = ux.Success
	} else {
		result = ux.Error
	}
	di.Analytics().AnalysisIsReady(ux.AnalysisIsReadyProperties{
		AnalysisType: ux.InfrastructureAsCode,
		Result:       result,
	})
}
