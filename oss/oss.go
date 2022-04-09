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

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}

func retrieveAnalysis(scanResults ossScanResult, uri sglsp.DocumentURI, doc sglsp.TextDocumentItem, dChan chan lsp.DiagnosticResult) {
	diags, err := retrieveDiagnostics(scanResults, doc)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanFile").Msg("Error while retrieving diagnositics")
	}

	if len(diags) > 0 {
		log.Debug().Str("method", "oss.ScanWorkspace").Msg("got diags, now sending to chan.")
		select {
		case dChan <- lsp.DiagnosticResult{
			Uri:         uri,
			Diagnostics: diags,
			Err:         err,
		}:
		default:
			log.Debug().Str("method", "oss.HandleFolder").Msg("not sending...")
		}
	}
}

func ScanWorkspace(workspace sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, clChan chan lsp.CodeLensResult) {
	log.Debug().Str("method", "oss.ScanWorkspace").Msg("started.")

	defer log.Debug().Str("method", "oss.ScanWorkspace").Msg("done.")
	defer wg.Done()

	path, _ := getDocAbsolutePath(workspace)
	cmd, err := createCliCmd(path, lsp.ScanWorkspace)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanWorkspace").Msg("Error while generating the CLI command")
	}

	scanResults, err := callSnykCLI(cmd)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanWorkspace").Msg(fmt.Sprintf("Error while calling Snyk CLI, err: %v", err))
	}

	targetFile := lockFilesToManifestMap[scanResults.DisplayTargetFile]
	fileContent, err := ioutil.ReadFile(path + "/" + targetFile)
	if err != nil {
		log.Err(err).Str("method", "oss.ScanWorkspace").Msgf("Error while reading the file %v, err: %v", targetFile, err)
		return
	}

	var uri = sglsp.DocumentURI(string(workspace) + "/" + targetFile)
	var doc = sglsp.TextDocumentItem{Text: string(fileContent)}

	retrieveAnalysis(scanResults, uri, doc, dChan)
}

func ScanFile(doc sglsp.TextDocumentItem, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, clChan chan lsp.CodeLensResult) {
	log.Debug().Str("method", "oss.ScanFile").Msg("started.")

	defer log.Debug().Str("method", "oss.ScanFile").Msg("done.")
	defer wg.Done()

	for _, supportedFile := range getDetectableFiles() {
		if strings.HasSuffix(string(doc.URI), supportedFile) {
			path, _ := getDocAbsolutePath(doc.URI)

			cmd, err := createCliCmd(path, lsp.ScanFile)

			if err != nil {
				log.Err(err).Str("method", "oss.ScanFile").Msg("Error while generating the CLI command")
			}

			scanResults, err := callSnykCLI(cmd)
			if err != nil {
				log.Err(err).Str("method", "oss.ScanFile").Msg("Error while calling Snyk CLI")
			}

			retrieveAnalysis(scanResults, doc.URI, doc, dChan)
		}
	}
}

func getDocAbsolutePath(docUri sglsp.DocumentURI) (string, error) {
	absolutePath, err := filepath.Abs(strings.ReplaceAll(string(docUri), "file://", ""))
	if err != nil {
		return "", err
	}

	log.Debug().Msg("OSS: Absolute Path: " + absolutePath)
	return absolutePath, nil
}

func createCliCmd(absolutePath string, level lsp.ScanLevel) (*exec.Cmd, error) {
	var cmd *exec.Cmd

	if level == lsp.ScanFile {
		cmd = exec.Command(environment.CliPath(), "test", "--file="+absolutePath, "--json")
	} else {
		cmd = exec.Command(environment.CliPath(), "test", absolutePath, "--json")
	}

	log.Debug().Msg(fmt.Sprintf("OSS: command: %s", cmd))
	return cmd, nil
}

func callSnykCLI(cmd *exec.Cmd) (ossScanResult, error) {
	log.Info().Msg(fmt.Sprintf("OSS: command: %s", cmd))
	resBytes, err := cmd.CombinedOutput()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				return ossScanResult{}, fmt.Errorf("error running %s, %s", cmd, err)
			}
		} else {
			return ossScanResult{}, fmt.Errorf("error running callSnykCLI: %s: ", err)
		}
	}

	var res ossScanResult
	if err := json.Unmarshal(resBytes, &res); err != nil {
		return ossScanResult{}, err
	}

	return res, nil
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

type ossScanResult struct {
	Vulnerabilities   []ossIssue `json:"vulnerabilities"`
	DisplayTargetFile string     `json:"displayTargetFile"`
}
