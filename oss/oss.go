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
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace/deleteme"
	"github.com/snyk/snyk-ls/domain/snyk/issues"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
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

type Scanner struct {
	instrumentor  performance.Instrumentor
	errorReporter error_reporting.ErrorReporter
	analytics     ux.Analytics
	cli           cli.Executor
}

func New(instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, analytics ux.Analytics, cli cli.Executor) *Scanner {
	return &Scanner{
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		analytics:     analytics,
		cli:           cli,
	}
}

func (oss *Scanner) IsSupported(documentURI sglsp.DocumentURI) bool {
	return supportedFiles[filepath.Base(uri.PathFromUri(documentURI))]
}

func (oss *Scanner) ScanWorkspace(ctx context.Context, documentURI sglsp.DocumentURI, output deleteme.ResultProcessor) {
	method := "oss.ScanWorkspace"
	s := oss.instrumentor.StartSpan(ctx, method)
	defer oss.instrumentor.Finish(s)
	p := progress.NewTracker(false)
	p.Begin(fmt.Sprintf("Scanning for Snyk Open Source issues in %s", documentURI), "Scanning Workspace.")
	defer p.End("Snyk Open Source scan completed.")

	defer log.Debug().Str("method", method).Msg("done.")
	log.Debug().Str("method", method).Msg("started.")

	workspacePath, err := filepath.Abs(uri.PathFromUri(documentURI))
	if err != nil {
		log.Err(err).Str("workspacePath", workspacePath).Msg("couldn't get absolute path")
	}
	cmd := oss.cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliPath(), "test", "--json"})
	res, err := oss.cli.Execute(cmd, workspacePath)
	if err != nil {
		if oss.handleError(err, res) {
			return
		}
	}

	oss.unmarshallAndRetrieveAnalysis(res, documentURI, output)

}

func (oss *Scanner) unmarshallAndRetrieveAnalysis(res []byte, documentURI sglsp.DocumentURI, output deleteme.ResultProcessor) {
	scanResults, done, err := oss.unmarshallOssJson(res)
	if err != nil {
		oss.errorReporter.CaptureError(err)
	}

	if done {
		return
	}

	for _, scanResult := range scanResults {
		targetFile := oss.determineTargetFile(scanResult.DisplayTargetFile)
		targetFilePath := filepath.Join(uri.PathFromUri(documentURI), targetFile)
		targetFileUri := uri.PathToUri(targetFilePath)
		fileContent, err := ioutil.ReadFile(targetFilePath)
		if err != nil {
			log.Err(err).Str("method", "unmarshallAndRetrieveAnalysis").
				Msgf("Error while reading the file %v, err: %v", targetFile, err)
			oss.errorReporter.CaptureError(err)
			return
		}
		oss.retrieveAnalysis(scanResult, targetFileUri, fileContent, output)
	}
}

func (oss *Scanner) unmarshallOssJson(res []byte) (scanResults []ossScanResult, done bool, err error) {
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

func (oss *Scanner) handleError(err error, res []byte) bool {
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
			oss.errorReporter.CaptureError(err)
			return true
		case 3:
			log.Debug().Str("method", "oss.Scan").Msg("no supported projects/files detected.")
			return true
		default:
			log.Err(err).Str("method", "oss.Scan").Msg("Error while calling Snyk CLI")
		}
	default:
		oss.errorReporter.CaptureError(err)
		return true
	}
	return true
}

func (oss *Scanner) determineTargetFile(displayTargetFile string) string {
	targetFile := lockFilesToManifestMap[displayTargetFile]
	if targetFile == "" {
		return displayTargetFile
	}
	return targetFile
}

func (oss *Scanner) ScanFile(
	ctx context.Context,
	documentURI sglsp.DocumentURI,
	output deleteme.ResultProcessor,
) {
	method := "oss.ScanFile"
	s := oss.instrumentor.StartSpan(ctx, method)
	defer oss.instrumentor.Finish(s)
	p := progress.NewTracker(false)
	p.Begin(fmt.Sprintf("Scanning for Snyk Open Source issues in %s", documentURI), "Scanning Single File.")
	defer p.End("Snyk Open Source scan completed.")

	log.Debug().Str("method", method).Msg("started.")
	defer log.Debug().Str("method", method).Msg("done.")

	if !oss.IsSupported(documentURI) {
		return
	}

	path, err := filepath.Abs(uri.PathFromUri(documentURI))
	if err != nil {
		log.Err(err).Str("method", method).
			Msg("Error while extracting file absolutePath")
	}
	workDir := filepath.Dir(path)
	cmd := oss.cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliPath(), "test", workDir, "--json"})
	res, err := oss.cli.Execute(cmd, workDir)
	if err != nil {
		if oss.handleError(err, res) {
			return
		}
	}

	oss.unmarshallAndRetrieveAnalysis(res, uri.PathToUri(workDir), output)
}

func (oss *Scanner) retrieveAnalysis(
	scanResults ossScanResult,
	documentURI sglsp.DocumentURI,
	fileContent []byte,
	output deleteme.ResultProcessor,
) {
	diagnostics, hoverDetails := oss.retrieveDiagnostics(scanResults, documentURI, fileContent)

	if len(diagnostics) > 0 {
		output(diagnostics, []hover.DocumentHovers{{Uri: documentURI, Hover: hoverDetails}})
	}
	oss.trackResult(true)
}

type RangeFinder interface {
	find(issue ossIssue) sglsp.Range
}

func (oss *Scanner) retrieveDiagnostics(
	res ossScanResult,
	uri sglsp.DocumentURI,
	fileContent []byte,
) ([]lsp.Diagnostic, []hover.Hover[hover.Context]) {
	var diagnostics []lsp.Diagnostic
	var hoverDetails []hover.Hover[hover.Context]

	// TODO write test for duplicate check
	duplicateCheckMap := map[string]bool{}

	for _, issue := range res.Vulnerabilities {
		key := issue.Id + "@" + issue.PackageName
		if duplicateCheckMap[key] {
			continue
		}
		issueRange := oss.findRange(issue, uri, fileContent)
		diagnostics = append(diagnostics, oss.toDiagnostics(issue, issueRange))
		hoverDetails = append(hoverDetails, oss.toHover(issue, issueRange))
		duplicateCheckMap[key] = true
	}

	return diagnostics, hoverDetails
}

func (oss *Scanner) toDiagnostics(issue ossIssue, issueRange sglsp.Range) lsp.Diagnostic {
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
		Severity: oss.lspSeverity(issue.Severity),
		Code:     issue.Id,
		// Don't use it for now as it's not widely supported
		// CodeDescription: lsp.CodeDescription{
		//	Href: issue.References[0].Url,
		// },
	}
}

func (oss *Scanner) toHover(issue ossIssue, issueRange sglsp.Range) hover.Hover[hover.Context] {
	title := issue.Title
	description := issue.Description

	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
		description = string(markdown.ToHTML([]byte(description), nil, nil))
	}
	summary := fmt.Sprintf("### Vulnerability %s %s %s \n **Fixed in: %s | Exploit maturity: %s**",
		oss.createCveLink(issue.Identifiers.CVE),
		oss.createCweLink(issue.Identifiers.CWE),
		oss.createIssueUrl(issue.Id),
		oss.createFixedIn(issue.FixedIn),
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
			Severity:  oss.toIssueSeverity(issue.Severity),
			IssueType: issues.DependencyVulnerability,
		},
	}
	return h
}

func (oss *Scanner) lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := lspSeverities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}

func (oss *Scanner) toIssueSeverity(snykSeverity string) issues.Severity {
	sev, ok := issuesSeverity[snykSeverity]
	if !ok {
		return issues.Low
	}
	return sev
}

func (oss *Scanner) createCveLink(cve []string) string {
	var formattedCve string
	for _, c := range cve {
		formattedCve += fmt.Sprintf("| [%s](https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s)", c, c)
	}
	return formattedCve
}

func (oss *Scanner) createIssueUrl(id string) string {
	return fmt.Sprintf("| [%s](https://snyk.io/vuln/%s)", id, id)
}

func (oss *Scanner) createFixedIn(fixedIn []string) string {
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

func (oss *Scanner) createCweLink(cwe []string) string {
	var formattedCwe string
	for _, c := range cwe {
		id := strings.Replace(c, "CWE-", "", -1)
		formattedCwe += fmt.Sprintf("| [%s](https://cwe.mitre.org/data/definitions/%s.html)", c, id)
	}
	return formattedCwe
}

func (oss *Scanner) findRange(issue ossIssue, uri sglsp.DocumentURI, fileContent []byte) sglsp.Range {
	var foundRange sglsp.Range
	var finder RangeFinder
	switch issue.PackageManager {
	case "npm":
		finder = &NpmRangeFinder{uri: uri, fileContent: fileContent}
	case "maven":
		if strings.HasSuffix(string(uri), "pom.xml") {
			finder = &mavenRangeFinder{uri: uri, fileContent: fileContent}
		} else {
			finder = &DefaultFinder{uri: uri, fileContent: fileContent}
		}
	default:
		finder = &DefaultFinder{uri: uri, fileContent: fileContent}
	}

	foundRange = finder.find(issue)
	return foundRange
}

func (oss *Scanner) trackResult(success bool) {
	var result ux.Result
	if success {
		result = ux.Success
	} else {
		result = ux.Error
	}
	oss.analytics.AnalysisIsReady(ux.AnalysisIsReadyProperties{
		AnalysisType: ux.OpenSource,
		Result:       result,
	})
}
