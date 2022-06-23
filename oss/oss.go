package oss

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk/issues"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	lspSeverities = map[string]sglsp.DiagnosticSeverity{
		"high": sglsp.Error,
		"low":  sglsp.Warning,
	}
	issuesSeverity = map[string]issues.Severity{
		"high": issues.High,
		"low":  issues.Medium,
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

func ScanWorkspace(ctx context.Context, cli cli.Executor, documentURI sglsp.DocumentURI, output func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers)) {
	method := "oss.ScanWorkspace"
	s := di.Instrumentor().StartSpan(ctx, method)
	defer di.Instrumentor().Finish(s)
	p := progress.NewTracker(false)
	p.Begin(fmt.Sprintf("Scanning for Snyk Open Source issues in %s", documentURI), "Scanning Workspace.")
	defer p.End("Snyk Open Source scan completed.")

	defer log.Debug().Str("method", method).Msg("done.")
	log.Debug().Str("method", method).Msg("started.")

	workspacePath, err := filepath.Abs(uri.PathFromUri(documentURI))
	if err != nil {
		log.Err(err).Str("workspacePath", workspacePath).Msg("couldn't get absolute path")
	}
	cmd := cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliPath(), "test", "--json"})
	res, err := cli.Execute(cmd, workspacePath)
	if err != nil {
		if handleError(err, res) {
			return
		}
	}

	unmarshallAndRetrieveAnalysis(res, documentURI, output)

}

func unmarshallAndRetrieveAnalysis(res []byte, documentURI sglsp.DocumentURI, output func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers)) {
	scanResults, done, err := unmarshallOssJson(res)
	if err != nil {
		di.ErrorReporter().CaptureError(err)
	}

	if done {
		return
	}

	for _, scanResult := range scanResults {
		targetFile := determineTargetFile(scanResult.DisplayTargetFile)
		targetFilePath := filepath.Join(uri.PathFromUri(documentURI), targetFile)
		targetFileUri := uri.PathToUri(targetFilePath)
		fileContent, err := ioutil.ReadFile(targetFilePath)
		if err != nil {
			log.Err(err).Str("method", "unmarshallAndRetrieveAnalysis").
				Msgf("Error while reading the file %v, err: %v", targetFile, err)
			di.ErrorReporter().CaptureError(err)
			return
		}
		retrieveAnalysis(scanResult, targetFileUri, fileContent, output)
	}
}

func unmarshallOssJson(res []byte) (scanResults []ossScanResult, done bool, err error) {
	err = json.Unmarshal(res, &scanResults)
	if err != nil {
		switch err := err.(type) {
		case *json.UnmarshalTypeError:
			var scanResult ossScanResult
			// fallback: try to unmarshal into single object if not an array of scan results
			err2 := json.Unmarshal(res, &scanResult)
			if err2 != nil {
				log.Err(err).Str("method", "unmarshalOssJson").Msg("couldn't unmarshal response as array")
				log.Err(err2).Str("method", "unmarshalOssJson").Msg("couldn't unmarshal response as single result")
				return nil, true, err2
			}
			scanResults = append(scanResults, scanResult)
			return scanResults, false, err2
		default:
			log.Err(err).Str("method", "unmarshalOssJson").Msg("couldn't unmarshal response as array")
			return nil, true, err
		}
	}
	return scanResults, false, err
}

func handleError(err error, res []byte) bool {
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
			return false
		case 2:
			log.Err(err).Str("method", "oss.Scan").Str("output", errorOutput).Msg("Error while calling Snyk CLI")
			di.ErrorReporter().CaptureError(err)
			return true
		case 3:
			log.Debug().Str("method", "oss.Scan").Msg("no supported projects/files detected.")
			return true
		default:
			log.Err(err).Str("method", "oss.Scan").Msg("Error while calling Snyk CLI")
		}
	default:
		di.ErrorReporter().CaptureError(err)
		return true
	}
	return true
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
	cli cli.Executor,
	documentURI sglsp.DocumentURI,
	output func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers),
) {
	method := "oss.ScanFile"
	s := di.Instrumentor().StartSpan(ctx, method)
	defer di.Instrumentor().Finish(s)
	p := progress.NewTracker(false)
	p.Begin(fmt.Sprintf("Scanning for Snyk Open Source issues in %s", documentURI), "Scanning Single File.")
	defer p.End("Snyk Open Source scan completed.")

	log.Debug().Str("method", method).Msg("started.")
	defer log.Debug().Str("method", method).Msg("done.")

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
	res, err := cli.Execute(cmd, workDir)
	if err != nil {
		if handleError(err, res) {
			return
		}
	}

	unmarshallAndRetrieveAnalysis(res, uri.PathToUri(workDir), output)
}

func retrieveAnalysis(
	scanResults ossScanResult,
	documentURI sglsp.DocumentURI,
	fileContent []byte,
	output func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers),
) {
	diagnostics, hoverDetails := retrieveDiagnostics(scanResults, documentURI, fileContent)

	if len(diagnostics) > 0 {
		output(map[string][]lsp.Diagnostic{uri.PathFromUri(documentURI): diagnostics}, []hover.DocumentHovers{{Uri: documentURI, Hover: hoverDetails}})
	}
	trackResult(true)
}

type RangeFinder interface {
	Find(issue ossIssue) sglsp.Range
}

func retrieveDiagnostics(
	res ossScanResult,
	uri sglsp.DocumentURI,
	fileContent []byte,
) ([]lsp.Diagnostic, []hover.Hover[hover.Context]) {
	var diagnostics []lsp.Diagnostic
	var hoverDetails []hover.Hover[hover.Context]

	for _, issue := range res.Vulnerabilities {
		issueRange := findRange(issue, uri, fileContent)
		diagnostics = append(diagnostics, toDiagnostics(issue, issueRange))
		hoverDetails = append(hoverDetails, toHover(issue, issueRange))
	}

	return diagnostics, hoverDetails
}

func toDiagnostics(issue ossIssue, issueRange sglsp.Range) lsp.Diagnostic {
	title := issue.Title
	//description := issue.Description

	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
		//description = string(markdown.ToHTML([]byte(description), nil, nil))
	}
	return lsp.Diagnostic{
		Source:   "Snyk LS",
		Message:  fmt.Sprintf("%s affecting package %s. Fixed in: %s (Snyk)", title, issue.PackageName, issue.FixedIn),
		Range:    issueRange,
		Severity: lspSeverity(issue.Severity),
		Code:     issue.Id,
		// Don't use it for now as it's not widely supported
		// CodeDescription: lsp.CodeDescription{
		//	Href: issue.References[0].Url,
		// },
	}
}

func toHover(issue ossIssue, issueRange sglsp.Range) hover.Hover[hover.Context] {
	title := issue.Title
	description := issue.Description

	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
		description = string(markdown.ToHTML([]byte(description), nil, nil))
	}
	summary := fmt.Sprintf("### Vulnerability %s %s %s \n **Fixed in: %s | Exploit maturity: %s**",
		createCveLink(issue.Identifiers.CVE),
		createCweLink(issue.Identifiers.CWE),
		createIssueUrl(issue.Id),
		createFixedIn(issue.FixedIn),
		strings.ToUpper(issue.Severity),
	)

	h := hover.Hover[hover.Context]{
		Id:    issue.Id,
		Range: issueRange,
		Message: fmt.Sprintf("\n### %s: %s affecting %s package \n%s \n%s",
			issue.Id,
			title,
			issue.PackageName,
			summary,
			description,
		),
		Context: issues.Issue{
			ID:        issue.Id,
			Severity:  toIssueSeverity(issue.Severity),
			IssueType: issues.DependencyVulnerability,
		},
	}
	return h
}

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := lspSeverities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}

func toIssueSeverity(snykSeverity string) issues.Severity {
	sev, ok := issuesSeverity[snykSeverity]
	if !ok {
		return issues.Low
	}
	return sev
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

func trackResult(success bool) {
	var result ux.Result
	if success {
		result = ux.Success
	} else {
		result = ux.Error
	}
	di.Analytics().AnalysisIsReady(ux.AnalysisIsReadyProperties{
		AnalysisType: ux.OpenSource,
		Result:       result,
	})
}
