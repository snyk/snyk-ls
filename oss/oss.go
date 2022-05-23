package oss

import (
	"context"
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

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/observability/instrumentation"
	"github.com/snyk/snyk-ls/internal/preconditions"
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

var supportedFiles = map[string]bool{
	"yarn.lock":               true,
	"package-lock.json":       true,
	"package.json":            true,
	"Gemfile":                 true,
	"Gemfile.lock":            true,
	"pom.xml":                 true,
	"build.gradle":            true,
	"build.gradle.kts":        true,
	"build.sbt":               true,
	"Pipfile":                 true,
	"requirements.txt":        true,
	"Gopkg.lock":              true,
	"go.mod":                  true,
	"vendor/vendor.json":      true,
	"obj/project.assets.json": true,
	"project.assets.json":     true,
	"packages.config":         true,
	"paket.dependencies":      true,
	"composer.lock":           true,
	"Podfile":                 true,
	"Podfile.lock":            true,
	"poetry.lock":             true,
	"mix.exs":                 true,
	"mix.lock":                true,
}

func IsSupported(documentURI sglsp.DocumentURI) bool {
	return supportedFiles[filepath.Base(uri.PathFromUri(documentURI))]
}

func ScanWorkspace(ctx context.Context, Cli cli.Executor, workspace sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	defer wg.Done()
	s := instrumentation.New()
	method := "oss.ScanWorkspace"
	s.StartSpan(ctx, method)
	defer s.Finish()
	defer log.Debug().Str("method", method).Msg("done.")
	log.Debug().Str("method", method).Msg("started.")

	workspacePath := uri.PathFromUri(workspace)
	path, err := filepath.Abs(workspacePath)
	if err != nil {
		log.Err(err).Str("method", method).
			Msg("Error while extracting file absolutePath")
	}

	cmd := cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliPath(), "test", path, "--json"})
	res, err := Cli.Execute(cmd, workspacePath)
	if err != nil {
		if handleError(err, res, workspace, dChan) {
			return
		}
	}

	var scanResult ossScanResult
	err = json.Unmarshal(res, &scanResult)
	if err != nil {
		log.Err(err).Str("method", method).Msg("couldn't unmarshal response")
		reportErrorViaChan(workspace, dChan, err)
		return
	}

	targetFile := determineTargetFile(scanResult.DisplayTargetFile)
	targetFilePath := filepath.Join(workspacePath, targetFile)
	targetFileUri := uri.PathToUri(targetFilePath)
	fileContent, err := ioutil.ReadFile(targetFilePath)
	if err != nil {
		log.Err(err).Str("method", method).
			Msgf("Error while reading the file %v, err: %v", targetFile, err)
		reportErrorViaChan(targetFileUri, dChan, err)
		return
	}

	retrieveAnalysis(scanResult, targetFileUri, fileContent, dChan, hoverChan)
}

func handleError(err error, res []byte, workspace sglsp.DocumentURI, dChan chan lsp.DiagnosticResult) bool {
	switch err := err.(type) {
	case *exec.ExitError:
		// Exit codes
		//  Possible exit codes and their meaning:
		//
		//  0: success, no vulnerabilities found
		//  1: action_needed, vulnerabilities found
		//  2: failure, try to re-run command
		//  3: failure, no supported projects detected
		errorOutput := string(res)
		switch err.ExitCode() {
		case 1:
		case 2:
			log.Err(err).Str("method", "oss.Scan").Str("output", errorOutput).Msg("Error while calling Snyk CLI")
			reportErrorViaChan(workspace, dChan, fmt.Errorf("%v: %v", err, errorOutput))
			return true
		case 3:
			log.Debug().Str("method", "oss.Scan").Msg("no supported projects/files detected.")
			return true
		default:
			log.Err(err).Str("method", "oss.Scan").Msg("Error while calling Snyk CLI")
		}
	default:
		reportErrorViaChan(workspace, dChan, err)
		return true
	}
	return false
}

func determineTargetFile(displayTargetFile string) string {
	targetFile := lockFilesToManifestMap[displayTargetFile]
	if targetFile == "" {
		return displayTargetFile
	}
	return targetFile
}

func ScanFile(
	ctx context.Context,
	Cli cli.Executor,
	documentURI sglsp.DocumentURI,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	defer wg.Done()
	s := instrumentation.New()
	method := "oss.ScanFile"
	s.StartSpan(ctx, method)
	defer s.Finish()
	defer log.Debug().Str("method", method).Msg("done.")
	log.Debug().Str("method", method).Msg("started.")

	if !IsSupported(documentURI) {
		return
	}

	path, err := filepath.Abs(uri.PathFromUri(documentURI))
	if err != nil {
		log.Err(err).Str("method", method).
			Msg("Error while extracting file absolutePath")
	}
	preconditions.EnsureReadyForAnalysisAndWait(ctx)
	workDir := filepath.Dir(path)
	cmd := cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliPath(), "test", workDir, "--json"})
	res, err := Cli.Execute(cmd, workDir)
	if err != nil {
		if handleError(err, res, documentURI, dChan) {
			return
		}
	}

	var scanResults ossScanResult
	err = json.Unmarshal(res, &scanResults)
	if err != nil {
		log.Err(err).Str("method", method).Msg("couldn't unmarshal response")
		reportErrorViaChan(documentURI, dChan, err)
		return
	}

	fileContent, err := os.ReadFile(path)
	if err != nil {
		log.Err(err).Str("method", method).
			Msg("Error reading file " + path)
		reportErrorViaChan(documentURI, dChan, err)
		return
	}

	retrieveAnalysis(scanResults, documentURI, fileContent, dChan, hoverChan)
}

func reportErrorViaChan(uri sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, err error) chan lsp.DiagnosticResult {
	select {
	case dChan <- lsp.DiagnosticResult{
		Uri:         uri,
		Diagnostics: nil,
		Err:         err,
	}:
	default:
		log.Debug().Str("method", "oss.reportErrorViaChan").Msg("not sending...")
	}
	return dChan
}

func retrieveAnalysis(
	scanResults ossScanResult,
	uri sglsp.DocumentURI,
	fileContent []byte,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	diags, hoverDetails := retrieveDiagnostics(scanResults, uri, fileContent)

	if len(diags) > 0 {
		log.Debug().Str("method", "oss.retrieveAnalysis").Msg("got diags, now sending to chan.")
		select {
		case dChan <- lsp.DiagnosticResult{
			Uri:         uri,
			Diagnostics: diags,
		}:
			hoverChan <- lsp.Hover{
				Uri:   uri,
				Hover: hoverDetails,
			}
			log.Debug().Str("method", "oss.retrieveAnalysis").Int("diagnosticCount", len(diags)).Msg("found sth")
		default:
			log.Debug().Str("method", "oss.retrieveAnalysis").Msg("not sending...")
		}
	}
}

type RangeFinder interface {
	Find(issue ossIssue) sglsp.Range
}

func retrieveDiagnostics(
	res ossScanResult,
	uri sglsp.DocumentURI,
	fileContent []byte,
) ([]lsp.Diagnostic, []lsp.HoverDetails) {
	var diagnostics []lsp.Diagnostic
	var hoverDetails []lsp.HoverDetails

	for _, issue := range res.Vulnerabilities {
		title := issue.Title
		description := issue.Description

		if config.CurrentConfig().Format() == config.FormatHtml {
			title = string(markdown.ToHTML([]byte(title), nil, nil))
			description = string(markdown.ToHTML([]byte(description), nil, nil))
		}

		diagnostic := lsp.Diagnostic{
			Source:   "Snyk LSP",
			Message:  fmt.Sprintf("%s: %s", issue.Id, title),
			Range:    findRange(issue, uri, fileContent),
			Severity: lspSeverity(issue.Severity),
			Code:     issue.Id,
			// Don't use it for now as it's not widely supported
			// CodeDescription: lsp.CodeDescription{
			//	Href: issue.References[0].Url,
			// },
		}
		diagnostics = append(diagnostics, diagnostic)

		summary := fmt.Sprintf("### Vulnerability %s %s %s \n **Fixed in: %s | Exploit maturity: %s**",
			createCveLink(issue.Identifiers.CVE),
			createCweLink(issue.Identifiers.CWE),
			createIssueUrl(issue.Id),
			createFixedIn(issue.FixedIn),
			strings.ToUpper(issue.Severity),
		)

		hover := lsp.HoverDetails{
			Id:    issue.Id,
			Range: findRange(issue, uri, fileContent),
			Message: fmt.Sprintf("\n### %s: %s affecting %s package \n%s \n%s",
				issue.Id,
				title,
				issue.PackageName,
				summary,
				description,
			),
		}
		hoverDetails = append(hoverDetails, hover)
	}

	return diagnostics, hoverDetails
}

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}

func createCveLink(cve []string) string {
	var formattedCve string
	for _, c := range cve {
		formattedCve += fmt.Sprintf("| [%s](https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s)", c, c)
	}
	return formattedCve
}

func createIssueUrl(id string) string {
	return fmt.Sprintf("| [%s](https://snyk.io/vuln/%s)", id, id)
}

func createFixedIn(fixedIn []string) string {
	var f string
	if len(fixedIn) < 1 {
		f += "Not Fixed"
	} else {
		f += "@" + fixedIn[0]
		for _, version := range fixedIn[1:] {
			f += fmt.Sprintf(", %s", version)
		}
	}
	return f
}

func createCweLink(cwe []string) string {
	var formattedCwe string
	for _, c := range cwe {
		id := strings.Replace(c, "CWE-", "", -1)
		formattedCwe += fmt.Sprintf("| [%s](https://cwe.mitre.org/data/definitions/%s.html)", c, id)
	}
	return formattedCwe
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
