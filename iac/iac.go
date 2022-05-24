package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gomarkdown/markdown"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/observability/instrumentation"
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

	method := "iac.ScanWorkspace"
	s := instrumentation.StartSpan(ctx, method)
	defer s.Finish()

	defer log.Debug().Str("method", method).Msg("done.")
	log.Debug().Str("method", method).Msg("started.")

	res, err := Cli.Execute(cliCmd(documentURI), uri.PathFromUri(documentURI))
	if err != nil {
		switch err := err.(type) {
		case *exec.ExitError:
			if err.ExitCode() > 1 {
				errorOutput := string(res)
				if strings.Contains(errorOutput, "Could not find any valid IaC files") {
					return
				}
				log.Err(err).Str("method", method).Str("output", errorOutput).Msg("Error while calling Snyk CLI")
				reportErrorViaChan(documentURI, dChan, fmt.Errorf("%v: %v", err, errorOutput))
				return
			}
			log.Warn().Err(err).Str("method", method).Msg("Error while calling Snyk CLI")
		default:
			reportErrorViaChan(documentURI, dChan, err)
			return
		}
	}

	var scanResults []iacScanResult
	if err := json.Unmarshal(res, &scanResults); err != nil {
		log.Err(err).Str("method", method).
			Msg("Error while parsing response from CLI")
		reportErrorViaChan(documentURI, dChan, err)
		return
	}

	log.Info().Str("method", method).
		Msg("got diags now sending to chan.")
	for _, scanResult := range scanResults {
		u := uri.PathToUri(filepath.Join(uri.PathFromUri(documentURI), scanResult.TargetFile))
		retrieveAnalysis(u, scanResult, dChan, hoverChan)
	}
}

func reportErrorViaChan(uri sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, err error) {
	dChan <- lsp.DiagnosticResult{
		Uri: uri,
		Err: err,
	}
}

func ScanFile(ctx context.Context, Cli cli.Executor, documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	defer wg.Done()
	method := "iac.ScanFile"
	s := instrumentation.StartSpan(ctx, method)
	defer s.Finish()

	defer log.Debug().Str("method", method).Msg("done.")
	log.Debug().Str("method", method).Msg("started.")

	if !IsSupported(documentURI) {
		return
	}

	res, err := Cli.Execute(cliCmd(documentURI), filepath.Dir(uri.PathFromUri(documentURI)))
	if err != nil {
		switch err := err.(type) {
		case *exec.ExitError:
			if err.ExitCode() > 1 {
				errorOutput := string(res)
				if strings.Contains(errorOutput, "Could not find any valid IaC files") ||
					strings.Contains(errorOutput, "CustomError: Not a recognised option did you mean --file") {
					return
				}
				log.Err(err).Str("method", "iac.ScanFile").Str("output", errorOutput).Msg("Error while calling Snyk CLI")
				reportErrorViaChan(documentURI, dChan, fmt.Errorf("%v: %v", err, errorOutput))
				return
			}
			log.Warn().Err(err).Str("method", "iac.ScanFile").Msg("Error while calling Snyk CLI")
		default:
			reportErrorViaChan(documentURI, dChan, err)
			return
		}
	}

	var scanResults iacScanResult
	if err := json.Unmarshal(res, &scanResults); err != nil {
		log.Err(err).Str("method", "iac.ScanFile").
			Msg("Error while calling Snyk CLI")
		reportErrorViaChan(documentURI, dChan, err)
		return
	}

	log.Debug().Interface("iacScanResult", scanResults).Msg("got it all unmarshalled, general!")
	retrieveAnalysis(documentURI, scanResults, dChan, hoverChan)
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
