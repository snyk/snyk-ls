package oss

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	lockFilesToManifestMap = map[string]string{
		"Gemfile.lock":      "Gemfile",
		"package-lock.json": "package.json",
		"yarn.lock":         "package.json",
		"Gopkg.lock":        "Gopkg.toml",
		"go.sum":            "go.mod",
		"composer.lock":     "composer.json",
		"Podfile.lock":      "Podfile",
		"poetry.lock":       "pyproject.toml",
	}
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

func ScanWorkspace(
	workspace sglsp.DocumentURI,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	clChan chan lsp.CodeLensResult,
) {
	defer wg.Done()
	defer log.Debug().Str("method", "oss.ScanWorkspace").Msg("done.")

	log.Debug().Str("method", "oss.ScanWorkspace").Msg("started.")

	path, err := filepath.Abs(strings.ReplaceAll(strings.ReplaceAll(string(workspace), "file://", ""), "file:", ""))
	if err != nil {
		log.Err(err).Str("method", "oss.ScanWorkspace").
			Msg("Error while extracting file absolutePath")
	}

	if err != nil {
		log.Err(err).Str("method", "oss.ScanWorkspace").
			Msg("Error changing into workspace directory")
	}
	cmd := exec.Command(environment.CliPath(), "test", path, "--json")
	scanResults, err := scan(cmd)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanWorkspace").
			Msgf("Error while calling Snyk CLI, err: %v", err)
	}

	targetFile := determineTargetFile(scanResults.DisplayTargetFile)
	fileContent, err := ioutil.ReadFile(path + "/" + targetFile)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanWorkspace").
			Msgf("Error while reading the file %v, err: %v", targetFile, err)
		return
	}

	var uri = sglsp.DocumentURI(string(workspace) + "/" + targetFile)
	var doc = sglsp.TextDocumentItem{Text: string(fileContent)}

	retrieveAnalysis(scanResults, uri, doc, dChan)
}

func determineTargetFile(displayTargetFile string) string {
	targetFile := lockFilesToManifestMap[displayTargetFile]
	if targetFile == "" {
		return displayTargetFile
	}
	return targetFile
}

func ScanFile(
	doc sglsp.TextDocumentItem,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	clChan chan lsp.CodeLensResult,
) {
	defer wg.Done()
	defer log.Debug().Str("method", "oss.ScanFile").Msg("done.")

	log.Debug().Str("method", "oss.ScanFile").Msg("started.")

	for _, supportedFile := range getDetectableFiles() {
		uri := string(doc.URI)
		if strings.HasSuffix(uri, supportedFile) {
			path, err := filepath.Abs(strings.ReplaceAll(strings.ReplaceAll(uri, "file://", ""), "file:", ""))
			if err != nil {
				log.Err(err).Str("method", "oss.ScanFile").
					Msg("Error while extracting file absolutePath")
			}

			cmd := exec.Command(environment.CliPath(), "test", "--file="+path, "--json")
			scanResults, err := scan(cmd)
			if err != nil {
				log.Err(err).Str("method", "oss.ScanFile").
					Msg("Error while calling Snyk CLI")
			}

			retrieveAnalysis(scanResults, doc.URI, doc, dChan)
		}
	}
}

func scan(cmd *exec.Cmd) (ossScanResult, error) {
	log.Info().Str("method", "oss.scan").Msgf("Command: %s", cmd)

	resBytes, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				return ossScanResult{}, fmt.Errorf("error running %s, %s", cmd, err)
			}
		} else {
			return ossScanResult{}, fmt.Errorf("error while perforing OSS scan: %s: ", err)
		}
	}

	var res ossScanResult
	if err := json.Unmarshal(resBytes, &res); err != nil {
		return ossScanResult{}, err
	}

	return res, nil
}

func retrieveAnalysis(
	scanResults ossScanResult,
	uri sglsp.DocumentURI,
	doc sglsp.TextDocumentItem,
	dChan chan lsp.DiagnosticResult,
) {
	diags, err := retrieveDiagnostics(scanResults, doc)
	if err != nil {
		log.Err(err).Str("method", "oss.retrieveAnalysis").Msg("Error while retrieving diagnositics")
	}

	if len(diags) > 0 {
		log.Debug().Str("method", "oss.retrieveAnalysis").Msg("got diags, now sending to chan.")
		select {
		case dChan <- lsp.DiagnosticResult{
			Uri:         uri,
			Diagnostics: diags,
			Err:         err,
		}:
		default:
			log.Debug().Str("method", "oss.retrieveAnalysis").Msg("not sending...")
		}
	}
}

type RangeFinder interface {
	Find(issue ossIssue) sglsp.Range
}

func retrieveDiagnostics(res ossScanResult, doc sglsp.TextDocumentItem) ([]lsp.Diagnostic, error) {
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

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
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
