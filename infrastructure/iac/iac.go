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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/snyk/snyk-ls/infrastructure/utils"

	"github.com/gomarkdown/markdown"
	pkgerrors "github.com/pkg/errors"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/scans"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

var scanCount = 1
var _ types.ProductScanner = (*Scanner)(nil)

var (
	issueSeverities = map[string]types.Severity{
		"high": types.High,
		"low":  types.Low,
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
	cli           cli.Executor
	mutex         sync.Mutex
	runningScans  map[sglsp.DocumentURI]*scans.ScanProgress
	c             *config.Config
}

func New(c *config.Config, instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, cli cli.Executor) *Scanner {
	return &Scanner{
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		cli:           cli,
		mutex:         sync.Mutex{},
		runningScans:  map[sglsp.DocumentURI]*scans.ScanProgress{},
		c:             c,
	}
}

func (iac *Scanner) IsEnabled() bool {
	return config.CurrentConfig().IsSnykIacEnabled()
}

func (iac *Scanner) Product() product.Product {
	return product.ProductInfrastructureAsCode
}

func (iac *Scanner) SupportedCommands() []types.CommandName {
	return []types.CommandName{}
}

func (iac *Scanner) Scan(ctx context.Context, path types.FilePath, _ types.FilePath, _ *types.FolderConfig) (issues []types.Issue, err error) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "iac.Scan").Logger()
	if !c.NonEmptyToken() {
		logger.Info().Msg("not authenticated, not scanning")
		return issues, err
	}

	if ctx.Err() != nil {
		logger.Info().Msg("Canceling IAC scan - IAC scanner received cancellation signal")
		return issues, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	documentURI := uri.PathToUri(path) // todo get rid of lsp dep
	if !iac.isSupported(documentURI) {
		return issues, nil
	}
	p := progress.NewTracker(true) // todo - get progress trackers via DI
	go func() { p.CancelOrDone(cancel, ctx.Done()) }()
	p.BeginUnquantifiableLength("Scanning for Snyk IaC issues", string(path))
	defer p.EndWithMessage("Snyk Iac Scan completed.")

	var workspacePath types.FilePath
	if uri.IsUriDirectory(documentURI) {
		workspacePath = uri.PathFromUri(documentURI)
	} else {
		workspacePath = types.FilePath(filepath.Dir(string(uri.PathFromUri(documentURI))))
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
		logger.Debug().Msgf("Scan %v is done", i)
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
		} else { // If the scan was canceled, return empty results
			return issues, nil
		}
	}

	if err != nil {
		return issues, err
	}

	issues, err = iac.retrieveIssues(scanResults, issues, workspacePath)
	if err != nil {
		return nil, pkgerrors.Wrap(err, "unable to retrieve IaC issues")
	}

	return issues, nil
}

func (iac *Scanner) retrieveIssues(scanResults []iacScanResult, issues []types.Issue, workspacePath types.FilePath) ([]types.Issue, error) {
	if len(scanResults) > 0 {
		for _, s := range scanResults {
			isIgnored := ignorableIacErrorCodes[s.ErrorCode]
			if !isIgnored {
				analysisIssues, err := iac.retrieveAnalysis(s, workspacePath)
				if err != nil {
					return nil, pkgerrors.Wrap(err, "retrieve analysis")
				}

				issues = append(issues, analysisIssues...)
			}
		}
	}
	return issues, nil
}

func (iac *Scanner) isSupported(documentURI sglsp.DocumentURI) bool {
	ext := filepath.Ext(string(uri.PathFromUri(documentURI)))
	return uri.IsUriDirectory(documentURI) || extensions[ext]
}

func (iac *Scanner) doScan(ctx context.Context, documentURI sglsp.DocumentURI, workspacePath types.FilePath) (scanResults []iacScanResult, err error) {
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
		var errorType *exec.ExitError
		switch {
		case errors.As(err, &errorType):
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

				// FIXME: no gotos!
			ERR:
				var exitError *exec.ExitError
				errors.As(err, &exitError)
				errorOutput := string(res) + "\n\n\nSTDERR output:\n" + string(exitError.Stderr)
				iac.c.Logger().Err(err).Str("method", method).Str("output", errorOutput).Msg("Error while calling Snyk CLI")
				err = pkgerrors.Wrap(err, fmt.Sprintf("Error executing %v.\n%s", cmd, errorOutput))
				return nil, err
			}
		default:
			iac.c.Logger().Err(err).Str("method", method).Msg("Error while calling Snyk CLI")
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
			err = pkgerrors.Wrap(err, fmt.Sprintf("Cannot unmarshal %s", output))
			iac.c.Logger().Err(err).Str("method", method).Msg("Cannot unmarshal")
			return nil, err
		}
	} else {
		var scanResult iacScanResult
		if err = json.Unmarshal(res, &scanResult); err != nil {
			err = pkgerrors.Wrap(err, fmt.Sprintf("Cannot unmarshal %s", output))
			iac.c.Logger().Err(err).Str("method", method).Msg("Cannot unmarshal")
			return nil, err
		}
		scanResults = append(scanResults, scanResult)
	}

	return scanResults, nil
}

func (iac *Scanner) cliCmd(u sglsp.DocumentURI) []string {
	path, err := filepath.Abs(string(uri.PathFromUri(u)))
	if err != nil {
		iac.c.Logger().Err(err).Str("method", "iac.Scan").
			Msg("Error while extracting file absolutePath")
	}
	if uri.IsUriDirectory(u) {
		path = ""
	}
	cmd := iac.cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliSettings().Path(), "iac", "test", path, "--json"})
	iac.c.Logger().Debug().Msg(fmt.Sprintf("IAC: command: %s", cmd))
	return cmd
}

func (iac *Scanner) retrieveAnalysis(scanResult iacScanResult, workspacePath types.FilePath) ([]types.Issue, error) {
	targetFile := filepath.Join(string(workspacePath), scanResult.TargetFile)
	rawFileContent, err := os.ReadFile(targetFile)
	fileContentString := ""
	if err != nil {
		errorMessage := "Could not read file content from " + targetFile
		iac.c.Logger().Err(err).Msg(errorMessage)
		iac.errorReporter.CaptureErrorAndReportAsIssue(workspacePath, pkgerrors.Wrap(err, errorMessage))
	} else {
		fileContentString = string(rawFileContent)
	}

	iac.c.Logger().Debug().Msgf("found %v IAC issues for file %s", len(scanResult.IacIssues), targetFile)
	var issues []types.Issue

	for _, issue := range scanResult.IacIssues {
		if issue.LineNumber > 0 {
			issue.LineNumber -= 1
		} else {
			issue.LineNumber = 0
		}

		i, err := iac.toIssue(workspacePath, types.FilePath(targetFile), issue, fileContentString)
		if err != nil {
			return nil, pkgerrors.Wrap(err, "unable to convert IaC issue to Snyk issue")
		}

		issues = append(issues, i)
	}
	return issues, nil
}

// todo this needs to be pushed up to presentation
func (iac *Scanner) getExtendedMessage(issue iacIssue) string {
	title := issue.Title
	description := issue.IacDescription.Issue
	impact := issue.IacDescription.Impact
	resolve := issue.IacDescription.Resolve

	if iac.c.Format() == config.FormatHtml {
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

func (iac *Scanner) toIssue(workspacePath types.FilePath, affectedFilePath types.FilePath, issue iacIssue, fileContent string) (*snyk.Issue, error) {
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
		iac.c.Logger().Err(err).Msg("Cannot create code action")
	}

	additionalData, err := iac.toAdditionalData(affectedFilePath, issue)
	if err != nil {
		return nil, pkgerrors.Wrap(err, "unable to create IaC issue additional data")
	}

	result := &snyk.Issue{
		ID: issue.PublicID,
		Range: types.Range{
			Start: types.Position{Line: issue.LineNumber, Character: rangeStart},
			End:   types.Position{Line: issue.LineNumber, Character: rangeEnd},
		},
		Message:             title,
		FormattedMessage:    iac.getExtendedMessage(issue),
		Severity:            iac.toIssueSeverity(issue.Severity),
		ContentRoot:         workspacePath,
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductInfrastructureAsCode,
		IssueDescriptionURL: issueURL,
		IssueType:           types.InfrastructureIssue,
		CodeActions:         []types.CodeAction{action},
		AdditionalData:      additionalData,
	}

	fingerprint := utils.CalculateFingerprintFromAdditionalData(result)
	result.SetFingerPrint(fingerprint)
	result.AdditionalData = additionalData

	return result, nil
}

func (iac *Scanner) toAdditionalData(affectedFilePath types.FilePath, issue iacIssue) (snyk.IaCIssueData, error) {
	key := getIssueKey(affectedFilePath, issue)

	iacIssuePath, err := parseIacIssuePath(issue.Path)
	if err != nil {
		return snyk.IaCIssueData{}, pkgerrors.Wrap(err, "unable to parse IaC issue path")
	}

	return snyk.IaCIssueData{
		Key:           key,
		Title:         issue.Title,
		PublicId:      issue.PublicID,
		Documentation: iac.createIssueURL(issue.PublicID).String(),
		LineNumber:    issue.LineNumber,
		Issue:         issue.IacDescription.Issue,
		Impact:        issue.IacDescription.Impact,
		Resolve:       issue.IacDescription.Resolve,
		Path:          iacIssuePath,
		References:    issue.References,
	}, nil
}

func parseIacIssuePath(path []any) ([]string, error) {
	var pathTokens []string
	for _, p := range path {
		switch val := p.(type) {
		case int:
			pathTokens = append(pathTokens, strconv.Itoa(val))
		case float32:
			pathTokens = append(pathTokens, strconv.FormatFloat(float64(val), 'f', -1, 32))
		case float64:
			pathTokens = append(pathTokens, strconv.FormatFloat(val, 'f', -1, 64))
		case string:
			pathTokens = append(pathTokens, val)
		default:
			return nil, pkgerrors.Errorf("unexpected type %T for IaC issue path token: %v", val, val)
		}
	}
	return pathTokens, nil
}

func newIacCommand(codeActionTitle string, issueURL *url.URL) *types.CommandData {
	command := &types.CommandData{
		Title:     codeActionTitle,
		CommandId: types.OpenBrowserCommand,
		Arguments: []any{issueURL.String()},
	}
	return command
}

func (iac *Scanner) createIssueURL(id string) *url.URL {
	parse, err := url.Parse("https://security.snyk.io/rules/cloud/" + id)
	if err != nil {
		iac.errorReporter.CaptureError(pkgerrors.Wrap(err, "unable to create issue link for iac issue "+id))
	}
	return parse
}

func (iac *Scanner) toIssueSeverity(snykSeverity string) types.Severity {
	severity, ok := issueSeverities[snykSeverity]
	if !ok {
		return types.Medium
	}
	return severity
}

func getIssueKey(affectedFilePath types.FilePath, issue iacIssue) string {
	id := sha256.Sum256([]byte(string(affectedFilePath) + strconv.Itoa(issue.LineNumber) + issue.PublicID))
	return hex.EncodeToString(id[:16])
}
