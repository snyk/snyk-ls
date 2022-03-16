package oss

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

func HandleFile(doc sglsp.TextDocumentItem, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, clChan chan lsp.CodeLensResult) {
	log.Debug().Str("method", "oss.HandleFile").Msg("started.")
	defer log.Debug().Str("method", "oss.HandleFile").Msg("done.")
	defer wg.Done()
	for _, supportedFile := range getDetectableFiles() {
		if strings.HasSuffix(string(doc.URI), supportedFile) {
			diags, err := callSnykCLI(doc)
			if err != nil {
				log.Err(err).Str("method", "oss.HandleFile").Msg("Error while calling Snyk CLI")
			}
			if len(diags) > 0 {
				log.Debug().Str("method", "oss.HandleFile").Msg("got diags, now sending to chan.")
				select {
				case dChan <- lsp.DiagnosticResult{
					Uri:         doc.URI,
					Diagnostics: diags,
					Err:         err,
				}:
				default:
					log.Debug().Str("method", "oss.HandleFile").Msg("not sending...")
				}
			}
		}
	}
}

func callSnykCLI(doc sglsp.TextDocumentItem) ([]lsp.Diagnostic, error) {
	absolutePath, err := filepath.Abs(strings.ReplaceAll(string(doc.URI), "file://", ""))
	log.Debug().Msg("OSS: Absolute Path: " + absolutePath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(environment.CliPath(), "test", "--file="+absolutePath, "--json")
	log.Debug().Msg(fmt.Sprintf("OSS: command: %s", cmd))
	resBytes, err := cmd.CombinedOutput()
	log.Debug().Msg(fmt.Sprintf("OSS: response: %s", resBytes))
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
		title := issue.Title
		description := issue.Description
		if environment.Format == environment.FormatHtml {
			title = string(markdown.ToHTML([]byte(title), nil, nil))
			description = string(markdown.ToHTML([]byte(description), nil, nil))
		}
		diagnostic := lsp.Diagnostic{
			Source:   "Snyk LSP",
			Message:  fmt.Sprintf("%s: %s\n\n%s", issue.Id, title, description),
			Range:    findRange(issue, doc),
			Severity: lspSeverity(issue.Severity),
			Code:     issue.Id,
			// Don't use it for now as it's not widely supported
			// CodeDescription: lsp.CodeDescription{
			//	Href: issue.References[0].Url,
			// },
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics, nil
}

type RangeFinder interface {
	Find(issue ossIssue) sglsp.Range
}

func findRange(issue ossIssue, doc sglsp.TextDocumentItem) sglsp.Range {
	var foundRange sglsp.Range
	var finder RangeFinder
	switch issue.PackageManager {
	case "npm":
		finder = &NpmRangeFinder{doc: doc}
	case "maven":
		if strings.HasSuffix(string(doc.URI), "pom.xml") {
			finder = &MavenRangeFinder{doc: doc}
		} else {
			finder = &DefaultFinder{doc: doc}
		}
	default:
		finder = &DefaultFinder{doc: doc}
	}

	foundRange = finder.Find(issue)
	return foundRange
}

func introducingPackageAndVersion(issue ossIssue) (string, string) {
	var packageName string
	var version string
	if len(issue.From) > 1 {
		split := strings.Split(issue.From[1], "@")
		packageSplit := split[0]
		switch issue.PackageManager {
		case "maven":
			index := strings.LastIndex(packageSplit, ":")
			packageName = packageSplit[index+1:]
		default:
			packageName = packageSplit
		}
		version = split[1]
	} else {
		packageName = issue.Name
		version = issue.Version
	}
	log.Debug().Str("issueId", issue.Id).Str("IntroducingPackage", packageName).Str("IntroducingVersion", version).Msg("Introducing package and version")
	return packageName, version
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
