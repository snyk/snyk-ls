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

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/scans"
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
	analytics               ux2.Analytics
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

func NewCLIScanner(instrumentor performance.Instrumentor,
	errorReporter error_reporting.ErrorReporter,
	analytics ux2.Analytics,
	cli cli.Executor,
	learnService learn.Service,
	notifier noti.Notifier,
	c *config.Config,
) snyk.ProductScanner {
	scanner := CLIScanner{
		instrumentor:            instrumentor,
		errorReporter:           errorReporter,
		analytics:               analytics,
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
	return config.CurrentConfig().IsSnykOssEnabled()
}

func (cliScanner *CLIScanner) Product() product.Product {
	return product.ProductOpenSource
}

func (cliScanner *CLIScanner) Scan(ctx context.Context, path string, _ string) (issues []snyk.Issue, err error) {
	cliPathScan := cliScanner.isSupported(path)
	if !cliPathScan {
		log.Debug().Msgf("OSS Scan not supported for %s", path)
		return issues, nil
	}
	return cliScanner.scanInternal(ctx, path, cliScanner.prepareScanCommand)
}
func (cliScanner *CLIScanner) scanInternal(
	ctx context.Context,
	path string,
	commandFunc func(args []string) []string,
) (issues []snyk.Issue,
	err error) {
	method := "cliScanner.Scan"
	s := cliScanner.instrumentor.StartSpan(ctx, method)
	defer cliScanner.instrumentor.Finish(s)
	log.Debug().Str("method", method).Msg("started.")
	defer log.Debug().Str("method", method).Msg("done.")

	if ctx.Err() != nil {
		log.Debug().Msg("Cancelling OSS scan - OSS scanner received cancellation signal")
		return issues, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := progress.NewTracker(false)
	p.BeginUnquantifiableLength("Scanning for Snyk Open Source issues", path)
	defer p.EndWithMessage("Snyk Open Source scan completed.")

	path, err = filepath.Abs(path)
	if err != nil {
		log.Err(err).Str("method", method).
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

	cmd := commandFunc([]string{workDir})
	res, err := cliScanner.cli.Execute(ctx, cmd, workDir)
	noCancellation := ctx.Err() == nil
	if err != nil {
		if noCancellation {
			if cliScanner.handleError(path, err, res, cmd) {
				return nil, err
			}
		} else { // If scan was cancelled, return empty results
			return []snyk.Issue{}, nil
		}
	}

	issues = cliScanner.unmarshallAndRetrieveAnalysis(ctx, res, workDir, path)
	cliScanner.trackResult(true)

	cliScanner.mutex.Lock()
	log.Debug().Msgf("Scan %v is done", i)
	newScan.SetDone()
	cliScanner.mutex.Unlock()

	if issues != nil {
		cliScanner.scheduleRefreshScan(context.Background(), path)
	}
	return issues, nil
}

func (cliScanner *CLIScanner) prepareScanCommand(args []string) []string {
	cmd := cliScanner.cli.ExpandParametersFromConfig([]string{
		config.CurrentConfig().CliSettings().Path(),
		"test",
	})
	cmd = append(cmd, args...)
	cmd = append(cmd, "--json")
	additionalParams := config.CurrentConfig().CliSettings().AdditionalOssParameters
	for _, parameter := range additionalParams {
		if parameter == "" {
			continue
		}
		cmd = append(cmd, parameter)
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
		targetFilePath := path
		targetFile := cliScanner.determineTargetFile(scanResult.DisplayTargetFile)
		if targetFile != "" {
			targetFilePath = filepath.Join(workDir, targetFile)
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
			err = errors.Join(err, fmt.Errorf("Couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
	} else {
		var result scanResult
		err = json.Unmarshal(res, &result)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("Couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
		scanResults = append(scanResults, result)
	}
	return scanResults, err
}

// Returns true if CLI run failed, false otherwise
func (cliScanner *CLIScanner) handleError(path string, err error, res []byte, cmd []string) bool {
	var errorType *exec.ExitError
	switch {
	case errors.As(err, &errorType):
		// Exit codes
		//  Possible exit codes and their meaning:
		//
		//  0: success, no vulnerabilities found
		//  1: action_needed, vulnerabilities found
		//  2: failure, try to re-run command
		//  3: failure, no supported projects detected
		var exitError *exec.ExitError
		errors.As(err, &exitError)
		errorOutput := string(res) + "\n\n\nSTDERR:\n" + string(exitError.Stderr)
		newError := fmt.Errorf("Snyk CLI error returned status code > 0 for command %v. Output: %s", cmd, errorOutput)
		newError = errors.Join(newError, err)
		switch errorType.ExitCode() {
		case 1:
			return false
		case 2:
			log.Err(newError).Str("method", "cliScanner.Scan").Str("output", errorOutput).Msg("Error while calling Snyk CLI")
			// we want a user notification, but don't want to send it to sentry
			cliScanner.notifier.SendErrorDiagnostic(path, newError)
			return true
		case 3:
			log.Debug().Str("method", "cliScanner.Scan").Msg("no supported projects/files detected.")
			return true
		default:
			log.Err(newError).Str("method", "cliScanner.Scan").Msg("Error while calling Snyk CLI")
			cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, newError)
		}
	default:
		if !errors.Is(err, context.Canceled) {
			cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		}
		return true
	}
	return true
}

func (cliScanner *CLIScanner) determineTargetFile(displayTargetFile string) string {
	targetFile := lockFilesToManifestMap[displayTargetFile]
	if targetFile == "" {
		return displayTargetFile
	}
	return targetFile
}

func (cliScanner *CLIScanner) retrieveIssues(
	res *scanResult,
	path string,
	fileContent []byte,
) []snyk.Issue {
	issues := convertScanResultToIssues(
		res,
		path,
		fileContent,
		cliScanner.learnService,
		cliScanner.errorReporter,
		cliScanner.packageIssueCache,
	)

	// repopulate
	cliScanner.addVulnerabilityCountsToCache(issues)

	return issues
}

func (cliScanner *CLIScanner) trackResult(success bool) {
	var result ux2.Result
	if success {
		result = ux2.Success
	} else {
		result = ux2.Error
	}
	cliScanner.analytics.AnalysisIsReady(ux2.AnalysisIsReadyProperties{
		AnalysisType: ux2.OpenSource,
		Result:       result,
	})
}

// scheduleRefreshScan Schedules new scan after refreshScanWaitDuration once existing OSS results might be stale.
// The timer is reset if a new scan is scheduled before the previous one is executed.
// Cancelling the context will stop the timer and abort the scheduled scan.
func (cliScanner *CLIScanner) scheduleRefreshScan(ctx context.Context, path string) {
	logger := log.With().Str("method", "cliScanner.scheduleRefreshScan").Logger()
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
				logger.Info().Msg("Scheduled scan cancelled")
				return
			}

			cliScanner.analytics.AnalysisIsTriggered(
				ux2.AnalysisIsTriggeredProperties{
					AnalysisType:    []ux2.AnalysisType{ux2.OpenSource},
					TriggeredByUser: false,
				},
			)

			span := cliScanner.instrumentor.NewTransaction(context.WithValue(ctx, cliScanner.Product(), cliScanner),
				string(cliScanner.Product()),
				"cliScanner.scheduleNewScanIn")
			defer cliScanner.instrumentor.Finish(span)

			logger.Info().Msg("Starting scheduled scan")
			_, _ = cliScanner.Scan(span.Context(), path, "")
		case <-ctx.Done():
			logger.Info().Msg("Scheduled scan cancelled")
			timer.Stop()
			return
		}
	}()
}
