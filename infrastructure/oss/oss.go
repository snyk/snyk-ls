package oss

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
)

var (
	issuesSeverity = map[string]snyk.Severity{
		"high": snyk.High,
		"low":  snyk.Medium,
	}

	//todo do we really need this? shouldn't we simply ignore diagnostics in locks???
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
	analytics     ux2.Analytics
	cli           cli.Executor
}

func New(instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, analytics ux2.Analytics, cli cli.Executor) *Scanner {
	return &Scanner{
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		analytics:     analytics,
		cli:           cli,
	}
}

func (oss *Scanner) SupportedCommands() []snyk.CommandName {
	return []snyk.CommandName{}
}

func (oss *Scanner) IsEnabled() bool {
	return config.CurrentConfig().IsSnykOssEnabled()
}

func (oss *Scanner) Product() snyk.Product {
	return snyk.ProductOpenSource
}

func (oss *Scanner) Scan(ctx context.Context, path string, _ string, _ []string) (issues []snyk.Issue) {
	documentURI := uri.PathToUri(path) //todo get rid of lsp dep
	if !oss.isSupported(documentURI) {
		log.Debug().Msgf("OSS Scan not supported for %s", path)
		return issues
	}
	method := "oss.Scan"
	s := oss.instrumentor.StartSpan(ctx, method)
	defer oss.instrumentor.Finish(s)
	p := progress.NewTracker(false)
	p.Begin("Scanning for Snyk Open Source issues", path)
	defer p.End("Snyk Open Source scan completed.")

	log.Debug().Str("method", method).Msg("started.")
	defer log.Debug().Str("method", method).Msg("done.")

	path, err := filepath.Abs(uri.PathFromUri(documentURI))
	if err != nil {
		log.Err(err).Str("method", method).
			Msg("Error while extracting file absolutePath")
	}

	var workDir string
	if uri.IsDirectory(documentURI) {
		workDir = path
	} else {
		workDir = filepath.Dir(path)
	}

	cmd := oss.cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliSettings().Path(), "test", workDir, "--json"})
	res, err := oss.cli.Execute(cmd, workDir)
	if err != nil {
		if oss.handleError(err, res, cmd) {
			return
		}
	}

	issues = oss.unmarshallAndRetrieveAnalysis(res, uri.PathToUri(workDir))
	return issues
}

func (oss *Scanner) isSupported(documentURI sglsp.DocumentURI) bool {
	return uri.IsDirectory(documentURI) || supportedFiles[filepath.Base(uri.PathFromUri(documentURI))]
}

func (oss *Scanner) unmarshallAndRetrieveAnalysis(res []byte, documentURI sglsp.DocumentURI) (issues []snyk.Issue) {
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
		issues = oss.retrieveIssues(scanResult, targetFileUri, fileContent)

		oss.trackResult(true)
	}
	return issues
}

func (oss *Scanner) unmarshallOssJson(res []byte) (scanResults []ossScanResult, done bool, err error) {
	output := string(res)
	if strings.HasPrefix(output, "[") {
		err = json.Unmarshal(res, &scanResults)
		if err != nil {
			err = errors.Wrap(err, fmt.Sprintf("Couldn't unmarshal CLI response. Input: %s", output))
			return nil, true, err
		}
	} else {
		var scanResult ossScanResult
		err = json.Unmarshal(res, &scanResult)
		if err != nil {
			if err != nil {
				err = errors.Wrap(err, fmt.Sprintf("Couldn't unmarshal CLI response. Input: %s", output))
				return nil, true, err
			}
		}
		scanResults = append(scanResults, scanResult)
	}
	return scanResults, false, err
}

func (oss *Scanner) handleError(err error, res []byte, cmd []string) bool {
	switch errorType := err.(type) {
	case *exec.ExitError:
		// Exit codes
		//  Possible exit codes and their meaning:
		//
		//  0: success, no vulnerabilities found
		//  1: action_needed, vulnerabilities found
		//  2: failure, try to re-run command
		//  3: failure, no supported projects detected
		errorOutput := string(res)
		err = errors.Wrap(err, fmt.Sprintf("Snyk CLI error executing %v. Output: %s", cmd, errorOutput))
		switch errorType.ExitCode() {
		case 1:
			return false
		case 2:
			log.Err(err).Str("method", "oss.Scan").Str("output", errorOutput).Msg("Error while calling Snyk CLI")
			// we want a user notification, but don't want to send it to sentry
			notification.Send(sglsp.ShowMessageParams{
				Type:    sglsp.MTError,
				Message: fmt.Sprintf("Snyk encountered an error: %v", err),
			})
			return true
		case 3:
			log.Debug().Str("method", "oss.Scan").Msg("no supported projects/files detected.")
			return true
		default:
			log.Err(err).Str("method", "oss.Scan").Msg("Error while calling Snyk CLI")
			oss.errorReporter.CaptureError(err)
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

type RangeFinder interface {
	find(issue ossIssue) snyk.Range
}

func (oss *Scanner) retrieveIssues(
	res ossScanResult,
	documentUri sglsp.DocumentURI,
	fileContent []byte,
) []snyk.Issue {
	var issues []snyk.Issue

	// TODO write test for duplicate check
	duplicateCheckMap := map[string]bool{}

	for _, issue := range res.Vulnerabilities {
		key := issue.Id + "@" + issue.PackageName
		if duplicateCheckMap[key] {
			continue
		}
		issueRange := oss.findRange(issue, documentUri, fileContent)
		issues = append(issues, oss.toIssue(uri.PathFromUri(documentUri), issue, issueRange))
		duplicateCheckMap[key] = true
	}

	return issues
}

func (oss *Scanner) toIssue(affectedFilePath string, issue ossIssue, issueRange snyk.Range) snyk.Issue {
	title := issue.Title

	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
	}
	var action = "No fix available."
	var resolution = ""
	if issue.IsUpgradable {
		action = "Upgrade to:"
		resolution = issue.UpgradePath[1].(string)
	} else {
		if len(issue.FixedIn) > 0 {
			action = "No direct upgrade path, fixed in:"
			resolution = fmt.Sprintf("%s@%s", issue.PackageName, issue.FixedIn[0])
		}
	}

	message := fmt.Sprintf(
		"%s affecting package %s. %s %s (Snyk)",
		title,
		issue.PackageName,
		action,
		resolution,
	)
	return snyk.Issue{
		ID:                  issue.Id,
		Message:             message,
		FormattedMessage:    oss.getExtendedMessage(issue),
		Range:               issueRange,
		Severity:            oss.toIssueSeverity(issue.Severity),
		AffectedFilePath:    affectedFilePath,
		Product:             snyk.ProductOpenSource,
		IssueDescriptionURL: oss.createIssueURL(issue.Id),
		IssueType:           snyk.DependencyVulnerability,
	}
}

//todo this needs to be pushed up to presentation
func (oss *Scanner) getExtendedMessage(issue ossIssue) string {
	title := issue.Title
	description := issue.Description

	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
		description = string(markdown.ToHTML([]byte(description), nil, nil))
	}
	summary := fmt.Sprintf("### Vulnerability %s %s %s \n **Fixed in: %s | Exploit maturity: %s**",
		oss.createCveLink(issue.Identifiers.CVE),
		oss.createCweLink(issue.Identifiers.CWE),
		oss.createIssueUrlMarkdown(issue.Id),
		oss.createFixedIn(issue.FixedIn),
		strings.ToUpper(issue.Severity),
	)

	return fmt.Sprintf("\n### %s: %s affecting %s package \n%s \n%s", issue.Id, title, issue.PackageName, summary, description)
}

func (oss *Scanner) toIssueSeverity(snykSeverity string) snyk.Severity {
	sev, ok := issuesSeverity[snykSeverity]
	if !ok {
		return snyk.Low
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

func (oss *Scanner) createIssueUrlMarkdown(id string) string {
	return fmt.Sprintf("| [%s](%s)", id, oss.createIssueURL(id).String())
}

func (oss *Scanner) createIssueURL(id string) *url.URL {
	parse, err := url.Parse("https://snyk.io/vuln/" + id)
	if err != nil {
		oss.errorReporter.CaptureError(errors.Wrap(err, "unable to create issue link for oss issue "+id))
	}
	return parse
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

func (oss *Scanner) findRange(issue ossIssue, uri sglsp.DocumentURI, fileContent []byte) snyk.Range {
	var foundRange snyk.Range
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
	var result ux2.Result
	if success {
		result = ux2.Success
	} else {
		result = ux2.Error
	}
	oss.analytics.AnalysisIsReady(ux2.AnalysisIsReadyProperties{
		AnalysisType: ux2.OpenSource,
		Result:       result,
	})
}
