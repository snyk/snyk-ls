/*
 * © 2023 Snyk Limited
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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/scans"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

var (
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
	// Make sure CLIScanner implements the desired interfaces
	_ snyk.ProductScanner      = (*CLIScanner)(nil)
	_ snyk.InlineValueProvider = (*CLIScanner)(nil)
)

type CLIScanner struct {
	instrumentor            performance.Instrumentor
	errorReporter           error_reporting.ErrorReporter
	cli                     cli.Executor
	mutex                   *sync.Mutex
	packageScanMutex        *sync.Mutex
	runningScans            map[string]*scans.ScanProgress
	refreshScanWaitDuration time.Duration
	scheduledScan           *time.Timer
	scheduledScanMtx        *sync.Mutex
	scanCount               int
	learnService            learn.Service
	notifier                noti.Notifier
	inlineValues            inlineValueMap
	supportedFiles          map[string]bool
	packageIssueCache       map[string][]snyk.Issue
	config                  *config.Config
}

func NewCLIScanner(c *config.Config, instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, cli cli.Executor, learnService learn.Service, notifier noti.Notifier) snyk.ProductScanner {
	scanner := CLIScanner{
		instrumentor:            instrumentor,
		errorReporter:           errorReporter,
		cli:                     cli,
		mutex:                   &sync.Mutex{},
		packageScanMutex:        &sync.Mutex{},
		scheduledScanMtx:        &sync.Mutex{},
		runningScans:            map[string]*scans.ScanProgress{},
		refreshScanWaitDuration: 24 * time.Hour,
		scanCount:               1,
		learnService:            learnService,
		notifier:                notifier,
		inlineValues:            make(inlineValueMap),
		packageIssueCache:       make(map[string][]snyk.Issue),
		config:                  c,
		supportedFiles: map[string]bool{
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
		},
	}
	return &scanner
}

func (cliScanner *CLIScanner) IsEnabled() bool {
	return cliScanner.config.IsSnykOssEnabled()
}

func (cliScanner *CLIScanner) Product() product.Product {
	return product.ProductOpenSource
}

func (cliScanner *CLIScanner) Scan(ctx context.Context, path string, _ string) (issues []snyk.Issue, err error) {
	logger := cliScanner.config.Logger().With().Str("method", "CLIScanner.scan").Logger()
	if !cliScanner.config.NonEmptyToken() {
		logger.Info().Msg("not authenticated, not scanning")
		return issues, err
	}
	cliPathScan := cliScanner.isSupported(path)
	if !cliPathScan {
		logger.Debug().Msgf("OSS Scan not supported for %s", path)
		return issues, nil
	}
	return cliScanner.scanInternal(ctx, path, cliScanner.prepareScanCommand)
}

func (cliScanner *CLIScanner) scanInternal(ctx context.Context, path string, commandFunc func(args []string, parameterBlacklist map[string]bool) []string) (issues []snyk.Issue, errorInfo error) {
	method := "cliScanner.Scan"
	logger := cliScanner.config.Logger().With().Str("method", method).Logger()

	s := cliScanner.instrumentor.StartSpan(ctx, method)
	defer cliScanner.instrumentor.Finish(s)
	logger.Debug().Str("method", method).Msg("started.")
	defer logger.Debug().Str("method", method).Msg("done.")

	if ctx.Err() != nil {
		logger.Debug().Msg("Canceling OSS scan - OSS scanner received cancellation signal")
		return issues, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := progress.NewTracker(false)
	p.BeginUnquantifiableLength("Scanning for Snyk Open Source issues", path)
	defer p.EndWithMessage("Snyk Open Source scan completed.")

	path, err := filepath.Abs(path)
	if errorInfo != nil {
		logger.Err(err).Str("method", method).
			Msg("Error while extracting file absolutePath")
	}

	var workDir string

	if uri.IsDirectory(path) {
		workDir = path
	} else {
		workDir = filepath.Dir(path)
	}

	cliScanner.mutex.Lock()
	i := cliScanner.scanCount
	previousScan, wasFound := cliScanner.runningScans[workDir]
	if wasFound && !previousScan.IsDone() { // If there's already a scan for the current workdir, we want to cancel it and restart it
		previousScan.CancelScan()
	}
	newScan := scans.NewScanProgress()
	go newScan.Listen(cancel, i)
	cliScanner.scanCount++
	cliScanner.runningScans[workDir] = newScan
	cliScanner.mutex.Unlock()

	cmd := commandFunc([]string{workDir}, map[string]bool{"": true})
	res, scanErr := cliScanner.cli.Execute(ctx, cmd, workDir)
	noCancellation := ctx.Err() == nil
	if scanErr != nil {
		if noCancellation {
			cliFailed, handledErr := cliScanner.handleError(path, scanErr, res, cmd)
			if cliFailed {
				return nil, handledErr
			}
		} else { // If scan was canceled, return empty results
			return []snyk.Issue{}, nil
		}
	}

	issues = cliScanner.unmarshallAndRetrieveAnalysis(ctx, res, workDir, path)

	cliScanner.mutex.Lock()
	logger.Debug().Msgf("Scan %v is done", i)
	newScan.SetDone()
	cliScanner.mutex.Unlock()

	if issues != nil {
		cliScanner.scheduleRefreshScan(context.Background(), path)
	}
	return issues, nil
}

func (cliScanner *CLIScanner) prepareScanCommand(args []string, parameterBlacklist map[string]bool) []string {
	cmd := cliScanner.cli.ExpandParametersFromConfig([]string{
		cliScanner.config.CliSettings().Path(),
		"test",
	})
	cmd = append(cmd, args...)
	cmd = append(cmd, "--json")
	additionalParams := cliScanner.config.CliSettings().AdditionalOssParameters
	for _, parameter := range additionalParams {
		if parameterBlacklist[parameter] {
			continue
		}
		cmd = append(cmd, parameter)
	}
	allProjectsParam := "--all-projects"
	if !slices.Contains(cmd, allProjectsParam) && !parameterBlacklist[allProjectsParam] {
		cmd = append(cmd, allProjectsParam)
	}

	return cmd
}

func (cliScanner *CLIScanner) isSupported(path string) bool {
	return uri.IsDirectory(path) || cliScanner.supportedFiles[filepath.Base(path)]
}

func (cliScanner *CLIScanner) unmarshallAndRetrieveAnalysis(ctx context.Context,
	res []byte,
	workDir string,
	path string,
) (issues []snyk.Issue) {
	if ctx.Err() != nil {
		return nil
	}

	scanResults, err := cliScanner.unmarshallOssJson(res)
	if err != nil {
		cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		return nil
	}

	for _, scanResult := range scanResults {
		targetFile := cliScanner.determineTargetFile(scanResult.DisplayTargetFile)
		targetFilePath := scanResult.Path
		if targetFilePath == "" {
			targetFilePath = workDir
		}
		if targetFilePath == "" {
			targetFilePath = targetFile
		} else {
			targetFilePath = filepath.Join(targetFilePath, targetFile)
		}
		fileContent, err := os.ReadFile(targetFilePath)
		if err != nil {
			// don't fail the scan if we can't read the file. No annotations with ranges, though.
			fileContent = []byte{}
		}
		issues = append(issues, cliScanner.retrieveIssues(&scanResult, targetFilePath, fileContent)...)
	}

	return issues
}

func (cliScanner *CLIScanner) unmarshallOssJson(res []byte) (scanResults []scanResult, err error) {
	output := string(res)
	if strings.HasPrefix(output, "[") {
		err = json.Unmarshal(res, &scanResults)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
	} else {
		var result scanResult
		err = json.Unmarshal(res, &result)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
		scanResults = append(scanResults, result)
	}
	return scanResults, err
}

// Returns true if CLI run failed, false otherwise
func (cliScanner *CLIScanner) handleError(path string, err error, res []byte, cmd []string) (bool, error) {
	cliError := &types.CliError{}
	unmarshalErr := json.Unmarshal(res, cliError)
	if unmarshalErr != nil {
		cliError.ErrorMessage = string(res)
		cliError.Command = fmt.Sprintf("%v", cmd)
	}

	logger := cliScanner.config.Logger().With().Str("method", "cliScanner.Scan").Str("output", cliError.ErrorMessage).Logger()

	var errorType *exec.ExitError
	switch {
	case errors.As(err, &errorType):
		// Exit codes
		//  Possible exit codes and their meaning:
		//
		//  0: success, no issues found
		//  1: action_needed, issues found
		//  2: failure, try to re-run command
		//  3: failure, no supported projects detected
		var exitError *exec.ExitError
		errors.As(err, &exitError)
		switch errorType.ExitCode() {
		case 1:
			return false, nil
		case 2:
			logger.Err(err).Msg("Error while calling Snyk CLI")
			// we want a user notification, but don't want to send it to sentry
			cliScanner.notifier.SendErrorDiagnostic(path, err)
		case 3:
			logger.Debug().Msg("no supported projects/files detected.")
		default:
			logger.Err(err).Msg("Error while calling Snyk CLI")
			cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		}
	default:
		if !errors.Is(err, context.Canceled) {
			cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		}
	}
	return true, cliError
}

func (cliScanner *CLIScanner) determineTargetFile(displayTargetFile string) string {
	fileName := filepath.Base(displayTargetFile)
	targetFileName := lockFilesToManifestMap[fileName]
	if targetFileName == "" {
		return displayTargetFile
	}
	targetFileName = strings.Replace(displayTargetFile, fileName, targetFileName, 1)
	return targetFileName
}

func (cliScanner *CLIScanner) retrieveIssues(
	res *scanResult,
	targetFilePath string,
	fileContent []byte,
) []snyk.Issue {
	// we are updating the cli scanner maps/attributes in parallel, so we need to lock
	cliScanner.mutex.Lock()
	defer cliScanner.mutex.Unlock()
	issues := convertScanResultToIssues(
		res,
		targetFilePath,
		fileContent,
		cliScanner.learnService,
		cliScanner.errorReporter,
		cliScanner.packageIssueCache,
	)

	// repopulate
	cliScanner.addVulnerabilityCountsToCache(issues)

	return issues
}

// scheduleRefreshScan Schedules new scan after refreshScanWaitDuration once existing OSS results might be stale.
// The timer is reset if a new scan is scheduled before the previous one is executed.
// Canceling the context will stop the timer and abort the scheduled scan.
func (cliScanner *CLIScanner) scheduleRefreshScan(ctx context.Context, path string) {
	logger := cliScanner.config.Logger().With().Str("method", "cliScanner.scheduleRefreshScan").Logger()
	cliScanner.scheduledScanMtx.Lock()
	if cliScanner.scheduledScan != nil {
		// Cancel previously scheduled scan
		cliScanner.scheduledScan.Stop()
	}

	timer := time.NewTimer(cliScanner.refreshScanWaitDuration)
	cliScanner.scheduledScan = timer
	cliScanner.scheduledScanMtx.Unlock()
	go func() {
		select {
		case <-timer.C:
			if !cliScanner.IsEnabled() {
				logger.Info().Msg("OSS scan is disabled, skipping scheduled scan")
				return
			}

			if ctx.Err() != nil {
				logger.Info().Msg("Scheduled scan canceled")
				return
			}

			span := cliScanner.instrumentor.NewTransaction(context.WithValue(ctx, cliScanner.Product(), cliScanner),
				string(cliScanner.Product()),
				"cliScanner.scheduleNewScanIn")
			defer cliScanner.instrumentor.Finish(span)

			logger.Info().Msg("Starting scheduled scan")
			_, _ = cliScanner.Scan(span.Context(), path, "")
		case <-ctx.Done():
			logger.Info().Msg("Scheduled scan canceled")
			timer.Stop()
			return
		}
	}()
}
