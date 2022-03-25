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

func ScanWorkspace(uri sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, clChan chan lsp.CodeLensResult) {
	defer wg.Done()
	defer log.Debug().Str("method", "iac.ScanWorkspace").Msg("done.")

	log.Debug().Str("method", "iac.ScanWorkspace").Msg("started.")

	absolutePath, _ := getDocAbsolutePath(uri)

	cmd := createCliCmd(absolutePath)
	res, err := callSnykCLI(cmd)
	if err != nil {
		log.Err(err).Str("method", "iac.ScanWorkspace").Msg("Error while calling Snyk CLI")
	}

	var scanResults []iacScanResult
	if err := json.Unmarshal(res, &scanResults); err != nil {
		log.Err(err).Str("method", "iac.ScanWorkspace").Msg("Error while parsing response from CLI")
	}

	log.Info().Str("method", "iac.ScanWorkspace").Msg("got diags & lenses, now sending to chan.")
	for i := 1; i < len(scanResults); i++ {
		scanResult := scanResults[i]

		diagnostics := convertDiagnostics(scanResult)
		codeLenses := convertCodeLenses(scanResult)

		if len(diagnostics) > 0 {
			select {
			case dChan <- lsp.DiagnosticResult{
				Uri:         sglsp.DocumentURI(string(uri) + "/" + scanResult.TargetFile),
				Diagnostics: diagnostics,
				Err:         err,
			}:
			default:
				log.Debug().Str("method", "fetch").Msg("no diags found & sent.")
			}
		}

		if len(codeLenses) > 0 {
			select {
			case clChan <- lsp.CodeLensResult{
				Uri:        sglsp.DocumentURI(string(uri) + "/" + scanResult.TargetFile),
				CodeLenses: codeLenses,
				Err:        err,
			}:
			default:
				log.Debug().Str("method", "fetch").Msg("no lens found & sent.")
			}
		}
	}
}

func ScanFile(uri sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, clChan chan lsp.CodeLensResult) {
	defer wg.Done()
	defer log.Debug().Str("method", "iac.ScanFile").Msg("done.")

	log.Debug().Str("method", "iac.ScanFile").Msg("started.")

	for _, supportedFile := range getDetectableFiles() {
		if strings.HasSuffix(string(uri), supportedFile) {
			absolutePath, _ := getDocAbsolutePath(uri)

			cmd := createCliCmd(absolutePath)
			res, err := callSnykCLI(cmd)
			if err != nil {
				log.Err(err).Str("method", "oss.ScanFile").Msg("Error while calling Snyk CLI")
			}

			var scanResults iacScanResult
			if err := json.Unmarshal(res, &res); err != nil {
				log.Err(err).Str("method", "iac.ScanFile").Msg("Error while calling Snyk CLI")
			}

			diagnostics := convertDiagnostics(scanResults)
			codeLenses := convertCodeLenses(scanResults)

			log.Debug().Str("method", "iac.ScanFile").Msg("got diags & lenses, now sending to chan.")
			if len(diagnostics) > 0 {
				select {
				case dChan <- lsp.DiagnosticResult{
					Uri:         uri,
					Diagnostics: diagnostics,
					Err:         err,
				}:
				default:
					log.Debug().Str("method", "fetch").Msg("no diags found & sent.")
				}
			}
			if len(codeLenses) > 0 {
				select {
				case clChan <- lsp.CodeLensResult{
					Uri:        uri,
					CodeLenses: codeLenses,
					Err:        err,
				}:
				default:
					log.Debug().Str("method", "fetch").Msg("no lens found & sent.")
				}
			}
		}
	}
}

func callSnykCLI(cmd *exec.Cmd) ([]byte, error) {
	defer log.Debug().Str("method", "fetch").Msg("done.")

	log.Debug().Str("method", "fetch").Msg("started.")

	resBytes, err := cmd.CombinedOutput()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				return nil, fmt.Errorf("error running %s, %s", cmd, err)
			}
		} else {
			return nil, fmt.Errorf("error running callSnykCLI: %s: ", err)
		}
	}

	return resBytes, nil
}

func getDocAbsolutePath(docUri sglsp.DocumentURI) (string, error) {
	absolutePath, err := filepath.Abs(strings.ReplaceAll(string(docUri), "file://", ""))
	if err != nil {
		return "", err
	}

	log.Debug().Msg("IAC: Absolute Path: " + absolutePath)
	return absolutePath, nil
}

func createCliCmd(absolutePath string) *exec.Cmd {
	cmd := exec.Command(environment.CliPath(), "iac", "test", absolutePath, "--json")
	log.Debug().Msg(fmt.Sprintf("IAC: command: %s", cmd))

	return cmd
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

type iacScanError struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
	Path  string `json:"path"`
}

type iacScanResult struct {
	TargetFile string `json:"targetFile`
	IacIssues  []struct {
		PublicID       string  `json:"publicId"`
		Title          string  `json:"title"`
		Severity       string  `json:"severity"`
		LineNumber     int     `json:"lineNumber"`
		Documentation  lsp.Uri `json:"documentation"`
		IacDescription struct {
			Issue   string `json:"issue"`
			Impact  string `json:"impact"`
			Resolve string `json:"resolve"`
		} `json:"iacDescription"`
	} `json:"infrastructureAsCodeIssues"`
}

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}
