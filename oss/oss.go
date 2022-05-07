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
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/cli"
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

var logger = environment.Logger

func IsSupported(documentURI sglsp.DocumentURI) bool {
	return supportedFiles[filepath.Base(uri.PathFromUri(documentURI))]
}

func ScanWorkspace(
	ctx context.Context,
	Cli cli.Executor,
	workspace sglsp.DocumentURI,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	defer wg.Done()
	logger.WithField("method", "oss.ScanWorkspace").Debug(ctx, "started")
	defer logger.WithField("method", "oss.ScanWorkspace").Debug(ctx, "done")

	workspacePath := uri.PathFromUri(workspace)
	path, err := filepath.Abs(workspacePath)
	if err != nil {
		logger.
			WithField("method", "oss.ScanWorkspace").
			WithError(err).
			Error(ctx, "couldn't get absolute path")
	}

	cmd := cli.ExpandParametersFromConfig(
		ctx,
		[]string{environment.CliPath(), "test", path, "--json"},
	)
	res, err := Cli.Execute(ctx, cmd)
	if err != nil {
		switch err := err.(type) {
		case *exec.ExitError:
			if err.ExitCode() > 1 {
				logger.
					WithField("method", "oss.ScanWorkspace").
					WithField("output", string(res)).
					WithError(err).
					Error(ctx, "Error while calling Snyk CLI")
				reportErrorViaChan(ctx, workspace, dChan, err)
				return
			}
			logger.
				WithField("method", "oss.ScanWorkspace").
				WithError(err).
				Warn(ctx, "exit code 1")
		default:
			reportErrorViaChan(ctx, workspace, dChan, err)
			return
		}
	}

	var scanResult ossScanResult
	err = json.Unmarshal(res, &scanResult)
	if err != nil {
		logger.
			WithField("method", "oss.ScanWorkspace").
			WithError(err).
			Error(ctx, "couldn't unmarshal response")
		reportErrorViaChan(ctx, workspace, dChan, err)
		return
	}

	targetFile := determineTargetFile(scanResult.DisplayTargetFile)
	targetFilePath := filepath.Join(workspacePath, targetFile)
	targetFileUri := uri.PathToUri(targetFilePath)
	fileContent, err := ioutil.ReadFile(targetFilePath)
	if err != nil {
		logger.
			WithField("method", "oss.ScanWorkspace").
			WithField("file", targetFile).
			WithError(err).
			Error(ctx, "Error while reading the file ")
		reportErrorViaChan(ctx, targetFileUri, dChan, err)
		return
	}

	retrieveAnalysis(ctx, scanResult, targetFileUri, fileContent, dChan, hoverChan)
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
	logger.WithField("method", "oss.ScanFile").Debug(ctx, "started")
	defer logger.WithField("method", "oss.ScanFile").Debug(ctx, "done")

	if !IsSupported(documentURI) {
		return
	}

	path, err := filepath.Abs(uri.PathFromUri(documentURI))
	if err != nil {
		logger.
			WithField("method", "oss.ScanFile").
			WithError(err).
			Error(ctx, "couldn't get absolute path")
	}
	preconditions.EnsureReadyForAnalysisAndWait()
	cmd := cli.ExpandParametersFromConfig(
		ctx,
		[]string{environment.CliPath(), "test", filepath.Dir(path), "--json"},
	)
	res, err := Cli.Execute(ctx, cmd)
	if err != nil {
		switch err := err.(type) {
		case *exec.ExitError:
			if err.ExitCode() > 1 {
				logger.
					WithField("method", "oss.ScanFile").
					WithField("output", string(res)).
					WithError(err).
					Error(ctx, "Error while calling Snyk CLI")
				reportErrorViaChan(ctx, documentURI, dChan, err)
				return
			}
			logger.
				WithField("method", "oss.ScanFile").
				WithField("output", string(res)).
				WithError(err).
				Warn(ctx, "exit code 1")
		default:
			reportErrorViaChan(ctx, documentURI, dChan, err)
			return
		}
	}

	var scanResults ossScanResult
	err = json.Unmarshal(res, &scanResults)
	if err != nil {
		logger.
			WithField("method", "oss.ScanFile").
			WithError(err).
			Error(ctx, "couldn't unmarshal response")
		reportErrorViaChan(ctx, documentURI, dChan, err)
		return
	}

	fileContent, err := os.ReadFile(path)
	if err != nil {
		logger.
			WithField("method", "oss.ScanFile").
			WithField("file", path).
			WithError(err).
			Error(ctx, "Error while reading the file ")
		reportErrorViaChan(ctx, documentURI, dChan, err)
		return
	}

	retrieveAnalysis(ctx, scanResults, documentURI, fileContent, dChan, hoverChan)
}

func reportErrorViaChan(ctx context.Context, uri sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, err error) chan lsp.DiagnosticResult {
	select {
	case dChan <- lsp.DiagnosticResult{
		Uri:         uri,
		Diagnostics: nil,
		Err:         err,
	}:
	default:
		logger.
			WithField("method", "oss.reportErrorViaChan").
			Debug(ctx, "not sending...")
	}
	return dChan
}

func retrieveAnalysis(
	ctx context.Context,
	scanResults ossScanResult,
	uri sglsp.DocumentURI,
	fileContent []byte,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	diags, hoverDetails, err := retrieveDiagnostics(scanResults, uri, fileContent)
	if err != nil {
		logger.
			WithField("method", "oss.retrieveAnalysis").
			WithError(err).
			Error(ctx, "Error while retrieving diagnostics")
		reportErrorViaChan(ctx, uri, dChan, err)
		return
	}

	if len(diags) > 0 {
		logger.
			WithField("method", "oss.retrieveAnalysis").
			Debug(ctx, "got diagnostics, now sending to chan.")
		select {
		case dChan <- lsp.DiagnosticResult{
			Uri:         uri,
			Diagnostics: diags,
		}:
			hoverChan <- lsp.Hover{
				Uri:   uri,
				Hover: hoverDetails,
			}
			logger.
				WithField("method", "oss.retrieveAnalysis").
				WithField("diagnosticCount", len(diags)).
				Debug(ctx, "found diagnostics")
		default:
			logger.
				WithField("method", "oss.retrieveAnalysis").
				Debug(ctx, "not sending")
		}
	}
}

func retrieveDiagnostics(
	res ossScanResult,
	uri sglsp.DocumentURI,
	fileContent []byte,
) ([]lsp.Diagnostic, []lsp.HoverDetails, error) {
	var diagnostics []lsp.Diagnostic
	var hoverDetails []lsp.HoverDetails

	for _, issue := range res.Vulnerabilities {
		title := issue.Title
		description := issue.Description

		if environment.Format == environment.FormatHtml {
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

	return diagnostics, hoverDetails, nil
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

	foundRange = finder.Find(context.Background(), issue)
	return foundRange
}
