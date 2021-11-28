package oss

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

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}

func HandleFile(uri sglsp.DocumentURI) ([]lsp.Diagnostic, error) {
	diagnostics, err := snyk(strings.TrimSpace(strings.ReplaceAll(string(uri), "file://", "")))
	return diagnostics, err
}

func snyk(path string) ([]lsp.Diagnostic, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(util.CliPath, "test", "--file="+path, "--json")
	cmd.Dir = filepath.Dir(path)
	resBytes, err := cmd.CombinedOutput()
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
	for _, issue := range res.Vulnerabilities {
		diagnostic := lsp.Diagnostic{
			Source:  "snyk-lsp",
			Message: fmt.Sprintf("%s: %s", issue.PublicID, issue.Title),
			Range: sglsp.Range{
				Start: sglsp.Position{Line: issue.LineNumber, Character: 0},
				End:   sglsp.Position{Line: issue.LineNumber, Character: 1},
			},
			Severity: lspSeverity(issue.Severity),
			Code:     fmt.Sprintf("%s", issue.PublicID),
			// Don't use it for now as it's not widely supported
			//CodeDescription: lsp.CodeDescription{
			//	Href: issue.References[0].Url,
			//},
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics, nil
}

type testResult struct {
	Vulnerabilities []struct {
		PublicID    string `json:"publicId"`
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		LineNumber  int    `json:"lineNumber"`
		Description string `json:"description"`
		References  []struct {
			Title string  `json:"title"`
			Url   lsp.Uri `json:"url"`
		} `json:"references"`
	} `json:"vulnerabilities"`
}
