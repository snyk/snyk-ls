package iac

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gomarkdown/markdown"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	severities = map[string]sglsp.DiagnosticSeverity{
		"high": sglsp.Error,
		"low":  sglsp.Warning,
	}
)

func getDetectableFiles() []string {
	return []string{
		"yaml",
		"yml",
		"json",
		"tf",
	}
}

func ScanWorkspace(
	uri sglsp.DocumentURI,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	clChan chan lsp.CodeLensResult,
) {
	defer wg.Done()
	defer log.Debug().Str("method", "iac.ScanWorkspace").Msg("done.")

	log.Debug().Str("method", "iac.ScanWorkspace").Msg("started.")

	res, err := scan(cliCmd(uri))
	if err != nil {
		log.Err(err).Str("method", "iac.ScanWorkspace").
			Msg("Error while calling Snyk CLI")
		reportErrorViaChan(uri, dChan, err, clChan)
		return
	}

	var scanResults []iacScanResult
	if err := json.Unmarshal(res, &scanResults); err != nil {
		log.Err(err).Str("method", "iac.ScanWorkspace").
			Msg("Error while parsing response from CLI")
		reportErrorViaChan(uri, dChan, err, clChan)
		return
	}

	log.Info().Str("method", "iac.ScanWorkspace").
		Msg("got diags & lenses, now sending to chan.")
	for _, scanResult := range scanResults {
		uri := sglsp.DocumentURI(string(uri) + "/" + scanResult.TargetFile)
		retrieveAnalysis(uri, scanResult, dChan, clChan, err)
	}
}

func reportErrorViaChan(uri sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, err error, clChan chan lsp.CodeLensResult) {
	dChan <- lsp.DiagnosticResult{
		Uri: uri,
		Err: err,
	}
	clChan <- lsp.CodeLensResult{
		Uri: uri,
		Err: err,
	}
}

func ScanFile(
	uri sglsp.DocumentURI,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	clChan chan lsp.CodeLensResult,
) {
	defer wg.Done()
	defer log.Debug().Str("method", "iac.ScanFile").Msg("done.")

	log.Debug().Str("method", "iac.ScanFile").Msg("started.")

	for _, supportedFile := range getDetectableFiles() {
		if strings.HasSuffix(string(uri), supportedFile) {
			res, err := scan(cliCmd(uri))
			if err != nil {
				log.Err(err).Str("method", "iac.ScanFile").
					Msg("Error while calling Snyk CLI")
			}

			var scanResults iacScanResult
			if err := json.Unmarshal(res, &scanResults); err != nil {
				log.Err(err).Str("method", "iac.ScanFile").
					Msg("Error while calling Snyk CLI")
			}

			retrieveAnalysis(uri, scanResults, dChan, clChan, err)
		}
	}
}

func cliCmd(u sglsp.DocumentURI) *exec.Cmd {
	path, err := filepath.Abs(uri.PathFromUri(u))
	if err != nil {
		log.Err(err).Str("method", "iac.ScanFile").
			Msg("Error while extracting file absolutePath")
	}

	cmd := exec.Command(environment.CliPath(), "iac", "test", path, "--json")
	log.Debug().Msg(fmt.Sprintf("IAC: command: %s", cmd))

	return cmd
}

func scan(cmd *exec.Cmd) ([]byte, error) {
	resBytes, err := cmd.CombinedOutput()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				return nil, fmt.Errorf("error running %s, %s", cmd, err)
			}
		} else {
			return nil, fmt.Errorf("error while performing IAC scan: %s: ", err)
		}
	}

	return resBytes, nil
}

func retrieveAnalysis(
	uri sglsp.DocumentURI,
	scanResult iacScanResult,
	dChan chan lsp.DiagnosticResult,
	clChan chan lsp.CodeLensResult,
	diagnosticsError error,
) {
	diagnostics := convertDiagnostics(scanResult)
	codeLenses := convertCodeLenses(scanResult)

	if len(diagnostics) > 0 {
		select {
		case dChan <- lsp.DiagnosticResult{
			Uri:         uri,
			Diagnostics: diagnostics,
			Err:         diagnosticsError,
		}:
		default:
			log.Debug().Str("method", "oss.retrieveAnalysis").Msg("no diags found & sent.")
		}
	}

	if len(codeLenses) > 0 {
		select {
		case clChan <- lsp.CodeLensResult{
			Uri:        uri,
			CodeLenses: codeLenses,
			Err:        diagnosticsError,
		}:
		default:
			log.Debug().Str("method", "oss.retrieveAnalysis").Msg("no lens found & sent.")
		}
	}
}

func convertCodeLenses(res iacScanResult) []sglsp.CodeLens {
	var lenses []sglsp.CodeLens
	for _, issue := range res.IacIssues {
		lens := sglsp.CodeLens{
			Range: sglsp.Range{
				Start: sglsp.Position{Line: issue.LineNumber - 1, Character: 0},
				End:   sglsp.Position{Line: issue.LineNumber - 1, Character: 80},
			},
			Command: sglsp.Command{
				Title:   "Show Description of " + issue.PublicID,
				Command: "snyk.launchBrowser",
				Arguments: []interface{}{
					issue.Documentation,
				},
			},
		}
		lenses = append(lenses, lens)
	}
	return lenses
}

func convertDiagnostics(res iacScanResult) []lsp.Diagnostic {
	var diagnostics []lsp.Diagnostic
	for _, issue := range res.IacIssues {
		title := issue.Title
		description := issue.IacDescription.Issue
		impact := issue.IacDescription.Impact
		resolve := issue.IacDescription.Resolve
		if environment.Format == environment.FormatHtml {
			title = string(markdown.ToHTML([]byte(title), nil, nil))
			description = string(markdown.ToHTML([]byte(description), nil, nil))
			impact = string(markdown.ToHTML([]byte(impact), nil, nil))
			resolve = string(markdown.ToHTML([]byte(resolve), nil, nil))
		}
		diagnostic := lsp.Diagnostic{
			Source: "Snyk LSP",
			Message: fmt.Sprintf("%s: %s\n\nIssue: %s\nImpact: %s\nResolve: %s\n",
				issue.PublicID, title, description, impact, resolve),
			Range: sglsp.Range{
				Start: sglsp.Position{Line: issue.LineNumber - 1, Character: 0},
				End:   sglsp.Position{Line: issue.LineNumber - 1, Character: 80},
			},
			Severity: lspSeverity(issue.Severity),
			Code:     issue.PublicID,
			// CodeDescription: lsp.CodeDescription{
			//	Href: issue.Documentation,
			// },
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics
}

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}
