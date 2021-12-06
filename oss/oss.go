package oss

import (
	"github.com/sirupsen/logrus"
	sglsp "github.com/sourcegraph/go-lsp"
)

import (
	"encoding/json"
	"fmt"
	"github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/util"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	severities = map[string]sglsp.DiagnosticSeverity{
		"high": sglsp.Error,
		"low":  sglsp.Warning,
	}
	logger *logrus.Logger
	// see https://github.com/snyk/snyk/blob/master/src/lib/detect.ts#L10
)

func getDetectableFiles() []string {
	return []string{
		"yarn.lock",
		"package-lock.json",
		"package.json",
		"Gemfile",
		"Gemfile.lock",
		"pom.xml",
		"build.gradle",
		"build.gradle.kts",
		"build.sbt",
		"Pipfile",
		"requirements.txt",
		"Gopkg.lock",
		"go.mod",
		"vendor/vendor.json",
		"obj/project.assets.json",
		"project.assets.json",
		"packages.config",
		"paket.dependencies",
		"composer.lock",
		"Podfile",
		"Podfile.lock",
		"poetry.lock",
		"mix.exs",
		"mix.lock",
	}
}

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}

func HandleFile(doc sglsp.TextDocumentItem) ([]lsp.Diagnostic, error) {
	for _, supportedFile := range getDetectableFiles() {
		if strings.HasSuffix(string(doc.URI), supportedFile) {
			return callSnykCLI(doc)
		}
	}
	return nil, nil
}

func callSnykCLI(doc sglsp.TextDocumentItem) ([]lsp.Diagnostic, error) {
	logger = logrus.New()
	absolutePath, err := filepath.Abs(strings.ReplaceAll(string(doc.URI), "file://", ""))
	logger.Info("OSS: Absolute Path: " + absolutePath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(util.CliPath, "test", "--file="+absolutePath, "--json")
	logger.Info(fmt.Sprintf("OSS: command: %s", cmd))
	resBytes, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				return nil, fmt.Errorf("error running %s, %s: %s", cmd, err, string(resBytes))
			}
		} else {
			return nil, fmt.Errorf("error running callSnykCLI: %s: %s", err, string(resBytes))
		}
	}
	var res testResult
	if err := json.Unmarshal(resBytes, &res); err != nil {
		return nil, err
	}
	var diagnostics []lsp.Diagnostic
	for _, issue := range res.Vulnerabilities {
		diagnostic := lsp.Diagnostic{
			Source:   "Snyk LSP",
			Message:  fmt.Sprintf("%s: %s\n\n%s", issue.Id, issue.Title, issue.Description),
			Range:    findRange(issue, doc),
			Severity: lspSeverity(issue.Severity),
			Code:     issue.Id,
			// Don't use it for now as it's not widely supported
			//CodeDescription: lsp.CodeDescription{
			//	Href: issue.References[0].Url,
			//},
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics, nil
}

// todo: this needs extensive testing
func findRange(issue ossIssue, doc sglsp.TextDocumentItem) sglsp.Range {
	lines := strings.Split(
		strings.ReplaceAll(doc.Text, "\r", ""),
		"\n")
	var lineStart, lineEnd, characterStart, characterEnd int
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		var packageName string
		if len(issue.From) >= 1 {
			split := strings.Split(issue.From[1], "@")
			packageName = fmt.Sprintf("\"%s\": \"", split[0])
		} else {
			packageName = fmt.Sprintf("\"%s\": \"", issue.Name)
		}
		if issue.PackageManager == "npm" {
			if strings.HasPrefix(
				strings.TrimSpace(strings.ReplaceAll(line, "^", "")), packageName) {
				lineStart = i
				lineEnd = i
				characterStart = strings.Index(line, packageName)
				characterEnd = len(line)
				break
			} else if issue.PackageManager == "maven" {
				// todo respect from
				packageName = strings.Split(strings.ReplaceAll(packageName, "\"", ""), ":")[0]
				if filepath.Base(string(doc.URI)) == "pom.xml" &&
					strings.Contains(
						line, fmt.Sprintf("<artifactId>%s</artifactId>", packageName),
					) {
					lineStart = i
					lineEnd = i
					characterStart = strings.Index(line, issue.Name)
					characterEnd = len(line)
					break
				} else {
					if strings.Contains(line, packageName) {
						lineStart = i
						lineEnd = i
						characterStart = strings.Index(line, packageName)
						characterEnd = len(line)
						break
					}
				}
			}
		}
	}
	// desperation run
	lineStart, lineEnd, characterStart, characterEnd =
		scanForContains(issue, lineStart, lineEnd, characterStart, characterEnd, lines)

	return sglsp.Range{
		Start: sglsp.Position{Line: lineStart, Character: characterStart},
		End:   sglsp.Position{Line: lineEnd, Character: characterEnd},
	}
}

func scanForContains(issue ossIssue, lineStart int, lineEnd int, characterStart int, characterEnd int, lines []string) (int, int, int, int) {
	if lineStart == 0 && lineEnd == 0 && characterStart == 0 && characterEnd == 0 {
		for i := 0; i < len(lines); i++ {
			line := lines[i]
			if strings.Contains(line, issue.Name) {
				lineStart = i
				lineEnd = i
				characterStart = strings.Index(line, issue.Name)
				characterEnd = characterStart + len(issue.Name)
				break
			}
		}
	}
	return lineStart, lineEnd, characterStart, characterEnd
}

type ossIssue struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	LineNumber  int    `json:"lineNumber"`
	Description string `json:"description"`
	References  []struct {
		Title string  `json:"title"`
		Url   lsp.Uri `json:"url"`
	} `json:"references"`
	Version        string   `json:"version"`
	PackageManager string   `json:"packageManager"`
	From           []string `json:"from"`
}

type testResult struct {
	Vulnerabilities []ossIssue `json:"vulnerabilities"`
}
