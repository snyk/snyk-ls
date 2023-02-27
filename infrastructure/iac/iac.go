/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

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
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/scans"
	"github.com/snyk/snyk-ls/internal/uri"
)

var scanCount = 1

var (
	issueSeverities = map[string]snyk.Severity{
		"high": snyk.High,
		"low":  snyk.Low,
	}
)

var extensions = map[string]bool{
	".yaml": true,
	".yml":  true,
	".json": true,
	".tf":   true,
}

type Scanner struct {
	instrumentor  performance.Instrumentor
	errorReporter error_reporting.ErrorReporter
	analytics     ux2.Analytics
	cli           cli.Executor
	mutex         sync.Mutex
	runningScans  map[sglsp.DocumentURI]*scans.ScanProgress
}

func New(instrumentor performance.Instrumentor,
	errorReporter error_reporting.ErrorReporter,
	analytics ux2.Analytics,
	cli cli.Executor,
) *Scanner {
	return &Scanner{
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		analytics:     analytics,
		cli:           cli,
		mutex:         sync.Mutex{},
		runningScans:  map[sglsp.DocumentURI]*scans.ScanProgress{},
	}
}

func (iac *Scanner) IsEnabled() bool {
	return config.CurrentConfig().IsSnykIacEnabled()
}

func (iac *Scanner) Product() product.Product {
	return product.ProductInfrastructureAsCode
}

func (iac *Scanner) SupportedCommands() []snyk.CommandName {
	return []snyk.CommandName{}
}

func (iac *Scanner) Scan(ctx context.Context, path string, _ string) (issues []snyk.Issue, err error) {
	if ctx.Err() != nil {
		log.Info().Msg("Cancelling IAC scan - IAC scanner received cancellation signal")
		return issues, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	documentURI := uri.PathToUri(path) // todo get rid of lsp dep
	if !iac.isSupported(documentURI) {
		return issues, nil
	}
	p := progress.NewTracker(false) // todo - get progress trackers via DI
	p.BeginUnquantifiableLength("Scanning for Snyk IaC issues", path)
	defer p.End("Snyk Iac Scan completed.")

	var workspacePath string
	if uri.IsUriDirectory(documentURI) {
		workspacePath = uri.PathFromUri(documentURI)
	} else {
		workspacePath = filepath.Dir(uri.PathFromUri(documentURI))
	}
	iac.mutex.Lock()
	i := scanCount
	previousScan, wasFound := iac.runningScans[documentURI]
	if wasFound && !previousScan.IsDone() { // If there's already a scan for the current workdir, we want to cancel it and restart it
		previousScan.CancelScan()
	}
	newScan := scans.NewScanProgress()
	go newScan.Listen(cancel, i)
	defer func() {
		iac.mutex.Lock()
		log.Debug().Msgf("Scan %v is done", i)
		newScan.SetDone() // Calling SetDone is safe even after cancellation
		iac.mutex.Unlock()
	}()
	scanCount++
	iac.runningScans[documentURI] = newScan
	iac.mutex.Unlock()

	scanResults, err := iac.doScan(ctx, documentURI, workspacePath)
	p.Report(80)
	if err != nil {
		noCancellation := ctx.Err() == nil
		if noCancellation { // Only reports errors that are not intentional cancellations
			iac.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		} else { // If the scan was cancelled, return empty results
			return issues, nil
		}
	}

	issues = iac.retrieveIssues(scanResults, issues, workspacePath, err)
	return issues, nil
}

func (iac *Scanner) retrieveIssues(scanResults []iacScanResult,
	issues []snyk.Issue,
	workspacePath string,
	err error,
) []snyk.Issue {
	if len(scanResults) > 0 {
		for _, s := range scanResults {
			isIgnored := ignorableIacErrorCodes[s.ErrorCode]
			if !isIgnored {
				issues = append(issues, iac.retrieveAnalysis(s, workspacePath)...)
			}
		}
	}
	iac.trackResult(err == nil)
	return issues
}

func (iac *Scanner) isSupported(documentURI sglsp.DocumentURI) bool {
	ext := filepath.Ext(uri.PathFromUri(documentURI))
	return uri.IsUriDirectory(documentURI) || extensions[ext]
}

func (iac *Scanner) doScan(ctx context.Context,
	documentURI sglsp.DocumentURI,
	workspacePath string,
) (scanResults []iacScanResult, err error) {
	method := "iac.doScan"
	s := iac.instrumentor.StartSpan(ctx, method)
	defer iac.instrumentor.Finish(s)

	// IAC scans can not run in parallel due to shared processes memory
	iac.mutex.Lock()
	defer iac.mutex.Unlock()

	cmd := iac.cliCmd(documentURI)
	res, err := iac.cli.Execute(ctx, cmd, workspacePath)

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if err != nil {
		switch errorType := err.(type) {
		case *exec.ExitError:
			const iacIssuesExitCode = 1
			if errorType.ExitCode() > iacIssuesExitCode { // Exit code > 1 == CLI has errors
				results, unmarshalErr := iac.unmarshal(res)
				// if results are all ignorable error codes, return empty scan results, otherwise return the error
				if unmarshalErr == nil && len(results) > 0 {
					for _, result := range results {
						if !ignorableIacErrorCodes[result.ErrorCode] {
							goto ERR
						}
					}
					return scanResults, nil // scanResults is empty
				}

			ERR:
				errorOutput := string(res) + "\n\n\nSTDERR output:\n" + string(err.(*exec.ExitError).Stderr)
				log.Err(err).Str("method", method).Str("output", errorOutput).Msg("Error while calling Snyk CLI")
				err = errors.Wrap(err, fmt.Sprintf("Snyk CLI error executing %v. Output: %s", cmd, errorOutput))
				return nil, err
			}
		default:
			log.Err(err).Str("method", method).Msg("Error while calling Snyk CLI")
			return nil, err
		}
	}

	return iac.unmarshal(res)
}

func (iac *Scanner) unmarshal(res []byte) (scanResults []iacScanResult, err error) {
	method := "iac.unmarshal"
	output := string(res)

	if strings.HasPrefix(output, "[") {
		if err = json.Unmarshal(res, &scanResults); err != nil {
			err = errors.Wrap(err, fmt.Sprintf("Cannot unmarshal %s", output))
			log.Err(err).Str("method", method).Msg("Cannot unmarshal")
			return nil, err
		}
	} else {
		var scanResult iacScanResult
		if err = json.Unmarshal(res, &scanResult); err != nil {
			err = errors.Wrap(err, fmt.Sprintf("Cannot unmarshal %s", output))
			log.Err(err).Str("method", method).Msg("Cannot unmarshal")
			return nil, err
		}
		scanResults = append(scanResults, scanResult)
	}

	return scanResults, nil
}

func (iac *Scanner) cliCmd(u sglsp.DocumentURI) []string {
	path, err := filepath.Abs(uri.PathFromUri(u))
	if err != nil {
		log.Err(err).Str("method", "iac.Scan").
			Msg("Error while extracting file absolutePath")
	}
	cmd := iac.cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliSettings().Path(), "iac", "test", path, "--json"})
	log.Debug().Msg(fmt.Sprintf("IAC: command: %s", cmd))
	return cmd
}

func (iac *Scanner) retrieveAnalysis(scanResult iacScanResult, workspacePath string) []snyk.Issue {
	targetFile := filepath.Join(workspacePath, scanResult.TargetFile)
	rawFileContent, err := os.ReadFile(targetFile)
	fileContentString := ""
	if err != nil {
		errorMessage := "Could not read file content from " + targetFile
		log.Err(err).Msg(errorMessage)
		iac.errorReporter.CaptureErrorAndReportAsIssue(workspacePath, errors.Wrap(err, errorMessage))
	} else {
		fileContentString = string(rawFileContent)
	}

	log.Debug().Msgf("found %v IAC issues for file %s", len(scanResult.IacIssues), targetFile)
	var issues []snyk.Issue

	for _, issue := range scanResult.IacIssues {
		if issue.LineNumber > 0 {
			issue.LineNumber -= 1
		} else {
			issue.LineNumber = 0
		}

		issues = append(issues, iac.toIssue(targetFile, issue, fileContentString))
	}
	return issues
}

func (iac *Scanner) trackResult(success bool) {
	var result ux2.Result
	if success {
		result = ux2.Success
	} else {
		result = ux2.Error
	}
	iac.analytics.AnalysisIsReady(
		ux2.AnalysisIsReadyProperties{
			AnalysisType: ux2.InfrastructureAsCode,
			Result:       result,
		},
	)
}

// todo this needs to be pushed up to presentation
func (iac *Scanner) getExtendedMessage(issue iacIssue) string {
	title := issue.Title
	description := issue.IacDescription.Issue
	impact := issue.IacDescription.Impact
	resolve := issue.IacDescription.Resolve

	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
		description = string(markdown.ToHTML([]byte(description), nil, nil))
		impact = string(markdown.ToHTML([]byte(impact), nil, nil))
		resolve = string(markdown.ToHTML([]byte(resolve), nil, nil))
	}

	return fmt.Sprintf(
		"\n### %s: %s\n\n**Issue:** %s\n\n**Impact:** %s\n\n**Resolve:** %s\n",
		issue.PublicID, title, description, impact, resolve,
	)

}

func (iac *Scanner) toIssue(affectedFilePath string, issue iacIssue, fileContent string) snyk.Issue {
	const defaultRangeStart = 0
	const defaultRangeEnd = 80
	title := issue.IacDescription.Issue
	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
	}
	codeActionTitle := fmt.Sprintf("Open description of '%s' in browser (Snyk)", issue.Title)

	// Try to gather the length of the line for the range
	rangeStart := defaultRangeStart
	rangeEnd := defaultRangeEnd
	if fileContent != "" {
		lines := strings.Split(strings.ReplaceAll(fileContent, "\r\n", "\n"), "\n")
		if len(lines) > (issue.LineNumber) {
			line := lines[issue.LineNumber]
			lineLength := len(line)
			trimmedLineLength := len(strings.TrimLeft(line, " "))
			leadingSpacesCount := lineLength - trimmedLineLength
			rangeStart = leadingSpacesCount
			rangeEnd = lineLength
		}
	}

	issueURL := iac.createIssueURL(issue.PublicID)
	command := newIacCommand(codeActionTitle, issueURL)
	action, err := snyk.NewCodeAction(codeActionTitle, nil, command)
	if err != nil {
		log.Err(err).Msg("Cannot create code action")
	}

	return snyk.Issue{
		ID: issue.PublicID,
		Range: snyk.Range{
			Start: snyk.Position{Line: issue.LineNumber, Character: rangeStart},
			End:   snyk.Position{Line: issue.LineNumber, Character: rangeEnd},
		},
		Message:             fmt.Sprintf("%s (Snyk)", title),
		FormattedMessage:    iac.getExtendedMessage(issue),
		Severity:            iac.toIssueSeverity(issue.Severity),
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductInfrastructureAsCode,
		IssueDescriptionURL: issueURL,
		IssueType:           snyk.InfrastructureIssue,
		CodeActions:         []snyk.CodeAction{action},
	}
}

func newIacCommand(codeActionTitle string, issueURL *url.URL) *snyk.Command {
	command := &snyk.Command{
		Title:     codeActionTitle,
		CommandId: snyk.OpenBrowserCommand,
		Arguments: []any{issueURL.String()},
	}
	return command
}

func (iac *Scanner) createIssueURL(id string) *url.URL {
	parse, err := url.Parse("https://snyk.io/security-rules/" + id)
	if err != nil {
		iac.errorReporter.CaptureError(errors.Wrap(err, "unable to create issue link for iac issue "+id))
	}
	return parse
}

func (iac *Scanner) toIssueSeverity(snykSeverity string) snyk.Severity {
	severity, ok := issueSeverities[snykSeverity]
	if !ok {
		return snyk.Medium
	}
	return severity
}
