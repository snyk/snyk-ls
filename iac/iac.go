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

	"github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/util"
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

func HandleFile(uri sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, clChan chan lsp.CodeLensResult) {
	defer wg.Done()
	log.Debug().Str("method", "iac.HandleFile").Msg("started.")
	defer log.Debug().Str("method", "iac.HandleFile").Msg("done.")
	for _, supportedFile := range getDetectableFiles() {
		if strings.HasSuffix(string(uri), supportedFile) {
			diags, lenses, err := fetch(string(uri))
			if err != nil {
				log.Err(err).Str("method", "iac.HandleFile").Msg("Error while calling Snyk CLI")
			}

			log.Debug().Str("method", "iac.HandleFile").Msg("got diags & lenses, now sending to chan.")
			if len(diags) > 0 {
				select {
				case dChan <- lsp.DiagnosticResult{
					Uri:         uri,
					Diagnostics: diags,
					Err:         err,
				}:
				default:
					log.Debug().Str("method", "fetch").Msg("no diags found & sent.")
				}
			}
			if len(lenses) > 0 {
				select {
				case clChan <- lsp.CodeLensResult{
					Uri:        uri,
					CodeLenses: lenses,
					Err:        err,
				}:
				default:
					log.Debug().Str("method", "fetch").Msg("no lens found & sent.")
				}
			}
		}
	}
}

func fetch(path string) ([]lsp.Diagnostic, []sglsp.CodeLens, error) {
	log.Debug().Str("method", "fetch").Msg("started.")
	defer log.Debug().Str("method", "fetch").Msg("done.")
	absolutePath, err := filepath.Abs(strings.ReplaceAll(path, "file://", ""))
	log.Debug().Msg("IAC: Absolute Path: " + absolutePath)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(util.CliPath(), "iac", "test", absolutePath, "--json")
	log.Debug().Msg(fmt.Sprintf("IAC: command: %s", cmd))
	resBytes, err := cmd.CombinedOutput()
	log.Debug().Msg(fmt.Sprintf("IAC: response: %s", resBytes))
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				return nil, nil, fmt.Errorf("error running %s: %s: %s", cmd, err, string(resBytes))
			}
		} else {
			return nil, nil, fmt.Errorf("error running fetch: %s: %s", err, string(resBytes))
		}
	}
	var res testResult
	if err := json.Unmarshal(resBytes, &res); err != nil {
		return nil, nil, err
	}
	diagnostics := convertDiagnostics(res)
	codeLenses := convertCodeLenses(res)
	return diagnostics, codeLenses, nil
}

func convertCodeLenses(res testResult) []sglsp.CodeLens {
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

func convertDiagnostics(res testResult) []lsp.Diagnostic {
	var diagnostics []lsp.Diagnostic
	for _, issue := range res.IacIssues {
		title := issue.Title
		description := issue.IacDescription.Issue
		impact := issue.IacDescription.Impact
		resolve := issue.IacDescription.Resolve
		if util.Format == util.FormatHtml {
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

type testResult struct {
	IacIssues []struct {
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
