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

package oss

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/scans"
	"github.com/snyk/snyk-ls/internal/uri"
)

var (
	issuesSeverity = map[string]snyk.Severity{
		"high": snyk.High,
		"low":  snyk.Medium,
	}

	// todo do we really need this? shouldn't we simply ignore diagnostics in locks???
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

// a counter for scans, used for logging
var scanCount = 1

type Scanner struct {
	instrumentor  performance.Instrumentor
	errorReporter error_reporting.ErrorReporter
	analytics     ux2.Analytics
	cli           cli.Executor
	mutex         *sync.Mutex
	runningScans  map[string]*scans.ScanProgress
}

func New(instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, analytics ux2.Analytics, cli cli.Executor) *Scanner {
	return &Scanner{
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		analytics:     analytics,
		cli:           cli,
		mutex:         &sync.Mutex{},
		runningScans:  map[string]*scans.ScanProgress{},
	}
}

func (oss *Scanner) SupportedCommands() []snyk.CommandName {
	return []snyk.CommandName{}
}

func (oss *Scanner) IsEnabled() bool {
	return config.CurrentConfig().IsSnykOssEnabled()
}

func (oss *Scanner) Product() product.Product {
	return product.ProductOpenSource
}

func (oss *Scanner) Scan(ctx context.Context, path string, _ string) (issues []snyk.Issue) {
	if ctx.Err() != nil {
		log.Debug().Msg("Cancelling OSS scan - OSS scanner received cancellation signal")
		return issues
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	documentURI := uri.PathToUri(path) // todo get rid of lsp dep
	if !oss.isSupported(documentURI) {
		log.Debug().Msgf("OSS Scan not supported for %s", path)
		return issues
	}
	method := "oss.Scan"
	s := oss.instrumentor.StartSpan(ctx, method)
	defer oss.instrumentor.Finish(s)
	p := progress.NewTracker(false)
	p.BeginUnquantifiableLength("Scanning for Snyk Open Source issues", path)
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

	oss.mutex.Lock()
	i := scanCount
	previousScan, wasFound := oss.runningScans[workDir]
	if wasFound && !previousScan.IsDone() { // If there's already a scan for the current workdir, we want to cancel it and restart it
		previousScan.CancelScan()
	}
	newScan := scans.NewScanProgress()
	go newScan.Listen(cancel, i)
	scanCount++
	oss.runningScans[workDir] = newScan
	oss.mutex.Unlock()

	cmd := oss.prepareScanCommand(workDir)
	res, err := oss.cli.Execute(ctx, cmd, workDir)
	noCancellation := ctx.Err() == nil
	if err != nil {
		if noCancellation {
			if oss.handleError(err, res, cmd) {
				return
			}
		} else { // If scan was cancelled, return empty results
			return
		}
	}

	issues = oss.unmarshallAndRetrieveAnalysis(ctx, res, uri.PathToUri(workDir))

	oss.mutex.Lock()
	log.Debug().Msgf("Scan %v is done", i)
	newScan.SetDone()
	oss.mutex.Unlock()

	return issues
}

func (oss *Scanner) prepareScanCommand(workDir string) []string {
	cmd := oss.cli.ExpandParametersFromConfig([]string{config.CurrentConfig().CliSettings().Path(), "test", workDir, "--json"})
	additionalParams := config.CurrentConfig().CliSettings().AdditionalOssParameters
	for _, parameter := range additionalParams {
		if parameter == "" {
			continue
		}
		cmd = append(cmd, parameter)
	}
	return cmd
}

func (oss *Scanner) isSupported(documentURI sglsp.DocumentURI) bool {
	return uri.IsDirectory(documentURI) || supportedFiles[filepath.Base(uri.PathFromUri(documentURI))]
}

func (oss *Scanner) unmarshallAndRetrieveAnalysis(ctx context.Context, res []byte, documentURI sglsp.DocumentURI) (issues []snyk.Issue) {
	if ctx.Err() != nil {
		return nil
	}

	scanResults, err := oss.unmarshallOssJson(res)
	if err != nil {
		oss.errorReporter.CaptureError(err)
		return nil
	}

	for _, scanResult := range scanResults {
		targetFile := oss.determineTargetFile(scanResult.DisplayTargetFile)
		targetFilePath := filepath.Join(uri.PathFromUri(documentURI), targetFile)
		targetFileUri := uri.PathToUri(targetFilePath)
		fileContent, err := os.ReadFile(targetFilePath)
		if err != nil {
			log.Err(err).Str("method", "unmarshallAndRetrieveAnalysis").
				Msgf("Error while reading the file %v, err: %v", targetFile, err)
			oss.errorReporter.CaptureError(err)
			return nil
		}
		issues = append(issues, oss.retrieveIssues(scanResult, targetFileUri, fileContent)...)
	}

	oss.trackResult(true)
	return issues
}

func (oss *Scanner) unmarshallOssJson(res []byte) (scanResults []ossScanResult, err error) {
	output := string(res)
	if strings.HasPrefix(output, "[") {
		err = json.Unmarshal(res, &scanResults)
		if err != nil {
			err = errors.Wrap(err, fmt.Sprintf("Couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
	} else {
		var scanResult ossScanResult
		err = json.Unmarshal(res, &scanResult)
		if err != nil {
			err = errors.Wrap(err, fmt.Sprintf("Couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
		scanResults = append(scanResults, scanResult)
	}
	return scanResults, err
}

// Returns true if CLI run failed, false otherwise
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
		exitError := err.(*exec.ExitError)
		errorOutput := string(res) + "\n\n\nSTDERR:\n" + string(exitError.Stderr)
		err = errors.Wrap(err, fmt.Sprintf("Snyk CLI error executing %v. Output: %s", cmd, errorOutput))
		switch errorType.ExitCode() {
		case 1:
			return false
		case 2:
			log.Err(err).Str("method", "oss.Scan").Str("output", errorOutput).Msg("Error while calling Snyk CLI")
			// we want a user notification, but don't want to send it to sentry
			notification.SendError(err)
			return true
		case 3:
			log.Debug().Str("method", "oss.Scan").Msg("no supported projects/files detected.")
			return true
		default:
			log.Err(err).Str("method", "oss.Scan").Msg("Error while calling Snyk CLI")
			oss.errorReporter.CaptureError(err)
		}
	default:
		if err != context.Canceled {
			oss.errorReporter.CaptureError(err)
		}
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
		FormattedMessage:    issue.getExtendedMessage(issue),
		Range:               issueRange,
		Severity:            issue.toIssueSeverity(),
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductOpenSource,
		IssueDescriptionURL: issue.createIssueURL(),
		IssueType:           snyk.DependencyVulnerability,
		CodeActions:         issue.GetCodeActions(),
	}
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
