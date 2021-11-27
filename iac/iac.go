package iac

import (
	"encoding/json"
	"fmt"
	"github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/util"
	sglsp "github.com/sourcegraph/go-lsp"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	severities = map[string]sglsp.DiagnosticSeverity{
		"high": sglsp.Error,
		"low":  sglsp.Warning,
	}
)

func HandleFile(uri sglsp.DocumentURI) ([]lsp.Diagnostic, error) {
	diagnostics, err := snyk(strings.ReplaceAll(string(uri), "file://", ""))
	return diagnostics, err
}

func snyk(path string) ([]lsp.Diagnostic, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	resBytes, err := exec.Command(util.CliPath, "iac", "test", path, "--json").CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				return nil, fmt.Errorf("error running snyk: %s: %s", err, string(resBytes))
			}
		} else {
			return nil, fmt.Errorf("error running snyk: %s: %s", err, string(resBytes))
		}
	}
	var res testResult
	if err := json.Unmarshal(resBytes, &res); err != nil {
		return nil, err
	}
	var diagnostics []lsp.Diagnostic
	for _, issue := range res.IacIssues {
		diagnostic := lsp.Diagnostic{
			Source:  "snyk-lsp",
			Message: fmt.Sprintf("%s: %s", issue.PublicID, issue.Title),
			Range: sglsp.Range{
				Start: sglsp.Position{Line: issue.LineNumber - 1, Character: 0},
				End:   sglsp.Position{Line: issue.LineNumber - 1, Character: 80},
			},
			Severity: lspSeverity(issue.Severity),
			// don't use for now as it's not widely supported
			//CodeDescription: lsp.CodeDescription{
			//	Href: issue.Documentation,
			//},
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics, nil
}

type testResult struct {
	IacIssues []struct {
		PublicID      string  `json:"publicId"`
		Title         string  `json:"title"`
		Severity      string  `json:"severity"`
		LineNumber    int     `json:"lineNumber"`
		Documentation lsp.Uri `json:"documentation"`
	} `json:"infrastructureAsCodeIssues"`
}

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}
