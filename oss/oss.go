package oss

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gomarkdown/markdown"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/snyk/cli"
	"github.com/snyk/snyk-ls/internal/uri"
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

func ScanWorkspace(Cli cli.Executor, workspace sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, clChan chan lsp.CodeLensResult) {
	defer wg.Done()
	defer log.Debug().Str("method", "oss.ScanWorkspace").Msg("done.")

	log.Debug().Str("method", "oss.ScanWorkspace").Msg("started.")

	workspacePath := uri.PathFromUri(workspace)
	path, err := filepath.Abs(workspacePath)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanWorkspace").
			Msg("Error while extracting file absolutePath")
	}

	cmd := []string{environment.CliPath(), "test", path, "--json"}
	res, err := Cli.Execute(cmd)
	if err != nil {
		if err.(*exec.ExitError).ExitCode() > 1 {
			log.Err(err).Str("method", "oss.ScanWorkspace").
				Msgf("Error while calling Snyk CLI, err: %v", err)
			reportErrorViaChan(workspace, dChan, err)
			return
		}
	}

	var scanResult ossScanResult
	err = json.Unmarshal(res, &scanResult)
	if err != nil {
		log.Err(err).Str("method", "scanWorkspace").Msg("couldn't unmarshal response")
		reportErrorViaChan(workspace, dChan, err)
		return
	}

	targetFile := determineTargetFile(scanResult.DisplayTargetFile)
	var workspaceUri = uri.PathToUri(filepath.Join(workspacePath, targetFile))
	fileContent, err := ioutil.ReadFile(path + "/" + targetFile)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanWorkspace").
			Msgf("Error while reading the fi le %v, err: %v", targetFile, err)
		reportErrorViaChan(workspace, dChan, err)
		return
	}

	retrieveAnalysis(scanResult, workspaceUri, fileContent, dChan)
}

func determineTargetFile(displayTargetFile string) string {
	targetFile := lockFilesToManifestMap[displayTargetFile]
	if targetFile == "" {
		return displayTargetFile
	}
	return targetFile
}

func ScanFile(Cli cli.Executor, documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, clChan chan lsp.CodeLensResult) {
	defer wg.Done()
	defer log.Debug().Str("method", "oss.ScanFile").Msg("done.")

	log.Debug().Str("method", "oss.ScanFile").Msg("started.")

	for _, supportedFile := range getDetectableFiles() {
		path := uri.PathFromUri(documentURI)
		if !strings.HasSuffix(path, supportedFile) {
			continue
		}
		path, err := filepath.Abs(path)
		if err != nil {
			log.Err(err).Str("method", "oss.ScanFile").
				Msg("Error while extracting file absolutePath")
		}

		cmd := []string{environment.CliPath(), "test", "--file=" + path, "--json"}
		res, err := Cli.Execute(cmd)
		if err != nil {
			if err.(*exec.ExitError).ExitCode() > 1 {
				log.Err(err).Str("method", "oss.ScanFile").
					Msgf("Error while calling Snyk CLI, err: %v", err)
				reportErrorViaChan(documentURI, dChan, err)
				return
			}
		}

		var scanResults ossScanResult
		err = json.Unmarshal(res, &scanResults)
		if err != nil {
			log.Err(err).Str("method", "scanFile").Msg("couldn't unmarshal response")
			reportErrorViaChan(documentURI, dChan, err)
			return
		}

		fileContent, err := os.ReadFile(path)
		if err != nil {
			log.Err(err).Str("method", "oss.ScanFile").
				Msg("Error reading file " + path)
			reportErrorViaChan(documentURI, dChan, err)
		}

		retrieveAnalysis(scanResults, documentURI, fileContent, dChan)
	}
}

func reportErrorViaChan(uri sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, err error) chan lsp.DiagnosticResult {
	select {
	case dChan <- lsp.DiagnosticResult{
		Uri:         uri,
		Diagnostics: nil,
		Err:         err,
	}:
	default:
		log.Debug().Str("method", "oss.retrieveAnalysis").Msg("not sending...")
	}
	return dChan
}

func retrieveAnalysis(
	scanResults ossScanResult,
	uri sglsp.DocumentURI,
	fileContent []byte,
	dChan chan lsp.DiagnosticResult,
) {
	diags, err := retrieveDiagnostics(scanResults, uri, fileContent)
	if err != nil {
		log.Err(err).Str("method", "oss.retrieveAnalysis").Msg("Error while retrieving diagnositics")
	}

	if len(diags) > 0 || err != nil {
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

func retrieveDiagnostics(res ossScanResult, uri sglsp.DocumentURI, fileContent []byte) ([]lsp.Diagnostic, error) {
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
			Range:    findRange(issue, uri, fileContent),
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

func findRange(issue ossIssue, uri sglsp.DocumentURI, fileContent []byte) sglsp.Range {
	var foundRange sglsp.Range
	var finder RangeFinder
	switch issue.PackageManager {
	case "npm":
		finder = &NpmRangeFinder{uri: uri, fileContent: fileContent}
	case "maven":
		if strings.HasSuffix(string(uri), "pom.xml") {
			finder = &MavenRangeFinder{uri: uri, fileContent: fileContent}
		} else {
			finder = &DefaultFinder{uri: uri, fileContent: fileContent}
		}
	default:
		finder = &DefaultFinder{uri: uri, fileContent: fileContent}
	}

	foundRange = finder.Find(issue)
	return foundRange
}
