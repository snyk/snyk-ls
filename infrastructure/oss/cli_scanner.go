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
	"github.com/snyk/snyk-ls/internal/sdk"
	storedConfig "github.com/snyk/snyk-ls/internal/storedconfig"
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

	allProjectsParamBlacklist = map[string]bool{
		"--file": true,
	}

	// Make sure CLIScanner implements the desired interfaces
	_ types.ProductScanner     = (*CLIScanner)(nil)
	_ snyk.InlineValueProvider = (*CLIScanner)(nil)
)

type CLIScanner struct {
	instrumentor            performance.Instrumentor
	errorReporter           error_reporting.ErrorReporter
	cli                     cli.Executor
	mutex                   *sync.RWMutex
	inlineValueMutex        *sync.RWMutex
	packageScanMutex        *sync.Mutex
	runningScans            map[types.FilePath]*scans.ScanProgress
	refreshScanWaitDuration time.Duration
	scheduledScan           *time.Timer
	scheduledScanMtx        *sync.Mutex
	scanCount               int
	learnService            learn.Service
	notifier                noti.Notifier
	inlineValues            inlineValueMap
	supportedFiles          map[string]bool
	packageIssueCache       map[string][]types.Issue
	config                  *config.Config
}

func NewCLIScanner(c *config.Config, instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, cli cli.Executor, learnService learn.Service, notifier noti.Notifier) types.ProductScanner {
	scanner := CLIScanner{
		instrumentor:            instrumentor,
		errorReporter:           errorReporter,
		cli:                     cli,
		mutex:                   &sync.RWMutex{},
		inlineValueMutex:        &sync.RWMutex{},
		packageScanMutex:        &sync.Mutex{},
		scheduledScanMtx:        &sync.Mutex{},
		runningScans:            map[types.FilePath]*scans.ScanProgress{},
		refreshScanWaitDuration: 24 * time.Hour,
		scanCount:               1,
		learnService:            learnService,
		notifier:                notifier,
		inlineValues:            make(inlineValueMap),
		packageIssueCache:       make(map[string][]types.Issue),
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

func (cliScanner *CLIScanner) Scan(ctx context.Context, path types.FilePath, _ types.FilePath, folderConfig *types.FolderConfig) (issues []types.Issue, err error) {
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
	return cliScanner.scanInternal(ctx, path, cliScanner.prepareScanCommand, folderConfig)
}

func (cliScanner *CLIScanner) scanInternal(ctx context.Context, path types.FilePath, commandFunc func(args []string, parameterBlacklist map[string]bool, path types.FilePath, folderConfig *types.FolderConfig) []string, folderConfig *types.FolderConfig) ([]types.Issue, error) {
	method := "cliScanner.Scan"
	logger := cliScanner.config.Logger().With().Str("method", method).Logger()

	s := cliScanner.instrumentor.StartSpan(ctx, method)
	defer cliScanner.instrumentor.Finish(s)
	logger.Debug().Str("method", method).Msg("started.")
	defer logger.Debug().Str("method", method).Msg("done.")

	if ctx.Err() != nil {
		logger.Debug().Msg("Canceling OSS scan - OSS scanner received cancellation signal")
		return []types.Issue{}, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := progress.NewTracker(true)
	go func() { p.CancelOrDone(cancel, ctx.Done()) }()
	p.BeginUnquantifiableLength("Scanning for Snyk Open Source issues", string(path))
	defer p.EndWithMessage("Snyk Open Source scan completed.")

	filePath, err := filepath.Abs(string(path))
	if err != nil {
		logger.Err(err).Str("method", method).
			Msg("Error while extracting file absolutePath")
	}

	var workDir types.FilePath

	if uri.IsDirectory(path) {
		workDir = path
	} else {
		workDir = types.FilePath(filepath.Dir(filePath))
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

	cmd := commandFunc([]string{string(workDir)}, map[string]bool{"": true}, workDir, folderConfig)
	res, scanErr := cliScanner.cli.Execute(ctx, cmd, workDir)
	noCancellation := ctx.Err() == nil
	if scanErr != nil {
		if noCancellation {
			cliFailed, handledErr := cliScanner.handleError(path, scanErr, res, cmd)
			if cliFailed {
				return nil, handledErr
			}
		} else { // If scan was canceled, return empty results
			return []types.Issue{}, nil
		}
	}

	issues := cliScanner.unmarshallAndRetrieveAnalysis(ctx, res, workDir, path)

	cliScanner.mutex.Lock()
	logger.Debug().Msgf("Scan %v is done", i)
	newScan.SetDone()
	cliScanner.mutex.Unlock()

	if issues != nil {
		cliScanner.scheduleRefreshScan(context.Background(), path)
	}
	return issues, nil
}

func (cliScanner *CLIScanner) updateArgs(workDir types.FilePath, commandLineArgs []string, folderConfig *types.FolderConfig) []string {
	if folderConfig == nil {
		folderConfig = cliScanner.config.FolderConfig(workDir)
	}
	folderConfigArgs := folderConfig.AdditionalParameters

	// this asks the client for the current SDK and blocks on it
	additionalParameters := cliScanner.updateSDKs(folderConfig.FolderPath)

	if len(folderConfigArgs) > 0 {
		additionalParameters = append(additionalParameters, folderConfigArgs...)
	}

	if len(additionalParameters) > 0 {
		for _, parameter := range additionalParameters {
			// if the sdk needs additional parameters, add them (Python plugin, I look at you. Yes, you)
			// the given parameters take precedence, meaning, a given python configuration will overrule
			// the automatically determined config
			isDuplicateParam := storedConfig.SliceContainsParam(commandLineArgs, parameter)
			if !isDuplicateParam {
				commandLineArgs = append(commandLineArgs, parameter)
			}
		}
	}
	return commandLineArgs
}

func (cliScanner *CLIScanner) updateSDKs(workDir types.FilePath) []string {
	logger := cliScanner.config.Logger().With().Str("method", "updateSDKs").Logger()
	sdkChan := make(chan []types.LsSdk)
	getSdk := types.GetSdk{FolderPath: string(workDir), Result: sdkChan}
	logger.Debug().Msg("asking IDE for SDKS")
	cliScanner.notifier.Send(getSdk)
	// wait for sdk info
	sdks := <-sdkChan
	logger.Debug().Msg("received SDKs")
	return sdk.UpdateEnvironmentAndReturnAdditionalParams(cliScanner.config, sdks)
}

func (cliScanner *CLIScanner) prepareScanCommand(args []string, parameterBlacklist map[string]bool, path types.FilePath, folderConfig *types.FolderConfig) []string {
	allProjectsParamAllowed := true
	allProjectsParam := "--all-projects"

	cmd := cliScanner.cli.ExpandParametersFromConfig([]string{
		cliScanner.config.CliSettings().Path(),
		"test",
	})
	args = cliScanner.updateArgs(path, args, folderConfig)
	cmd = append(cmd, args...)
	cmd = append(cmd, "--json")

	additionalParams := cliScanner.config.CliSettings().AdditionalOssParameters

	// now add all additional parameters, skipping blacklisted ones
	for _, parameter := range additionalParams {
		if storedConfig.SliceContainsParam(cmd, parameter) {
			continue
		}

		p := strings.Split(parameter, "=")[0]

		if parameterBlacklist[p] {
			continue
		}

		if allProjectsParamBlacklist[p] {
			allProjectsParamAllowed = false
		}

		if parameter != allProjectsParam {
			cmd = append(cmd, parameter)
		}
	}

	// only append --all-projects, if it's not on the global blacklist
	// and if there is no other parameter interfering (e.g. --file)
	allProjectsParamAllowed = allProjectsParamAllowed && !slices.Contains(cmd, allProjectsParam)
	if allProjectsParamAllowed && !parameterBlacklist[allProjectsParam] {
		cmd = append(cmd, allProjectsParam)
	}

	return cmd
}

func (cliScanner *CLIScanner) isSupported(path types.FilePath) bool {
	return uri.IsDirectory(path) || cliScanner.supportedFiles[filepath.Base(string(path))]
}

func (cliScanner *CLIScanner) unmarshallAndRetrieveAnalysis(ctx context.Context,
	res []byte,
	workDir types.FilePath,
	path types.FilePath,
) (issues []types.Issue) {
	logger := cliScanner.config.Logger().With().Str("method", "getAbsTargetFilePath").Logger()
	if ctx.Err() != nil {
		return nil
	}

	scanResults, err := cliScanner.unmarshallOssJson(res)
	if err != nil {
		cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		return nil
	}

	for _, scanResult := range scanResults {
		targetFilePath := getAbsTargetFilePath(cliScanner.config, scanResult, workDir, path)
		fileContent, err := os.ReadFile(string(targetFilePath))
		if err != nil {
			reportedErr := fmt.Errorf("skipping scanResult for path: %s displayTargetFile: %s in workDir: %s as we can't determine the absolute filesystem path. %w", scanResult.Path, scanResult.DisplayTargetFile, workDir, err)
			cliScanner.errorReporter.CaptureErrorAndReportAsIssue(targetFilePath, reportedErr)
			logger.Error().Err(reportedErr).Send()
			continue
		}
		issues = append(issues, cliScanner.retrieveIssues(&scanResult, workDir, targetFilePath, fileContent)...)
	}

	return issues
}

func getAbsTargetFilePath(c *config.Config, scanResult scanResult, workDir types.FilePath, path types.FilePath) types.FilePath {
	logger := c.Logger().With().Str("method", "getAbsTargetFilePath").Logger()
	if scanResult.DisplayTargetFile == "" && path != "" {
		return path
	}
	displayTargetFile := determineTargetFile(scanResult.DisplayTargetFile)

	// if displayTargetFile is an absolute path, no need to do anything more
	isAbs := filepath.IsAbs(displayTargetFile)
	if isAbs {
		return types.FilePath(displayTargetFile)
	}

	relative, err := filepath.Rel(string(workDir), displayTargetFile)
	if err != nil || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		logger.Trace().Err(err).Msgf("path is not relative to %s", workDir)
		// now we try out stuff
		// if displayTargetFile is not relative, let's try to join path with basename
		basePath := filepath.Base(displayTargetFile)
		scanResultPath := scanResult.Path
		tryOutPath := filepath.Join(scanResultPath, displayTargetFile)
		_, tryOutErr := os.Stat(tryOutPath)
		if tryOutErr != nil {
			logger.Trace().Err(err).Msgf("joining displayTargetFile: %s to path: %s failed", displayTargetFile, scanResultPath)
			tryOutPath = filepath.Join(scanResultPath, basePath)
			_, tryOutErr := os.Stat(tryOutPath)
			if tryOutErr != nil {
				logger.Trace().Err(err).Msgf("joining basePath: %s to path: %s failed", basePath, scanResultPath)
				// if that doesn't work, let's try full path and full display target file
				tryOutPath = filepath.Join(string(workDir), displayTargetFile)
				_, tryOutErr = os.Stat(tryOutPath)
				if tryOutErr != nil {
					logger.Trace().Err(err).Msgf("joining displayTargetFile: %s to workDir: %s failed.", displayTargetFile, workDir)
					tryOutPath = filepath.Join(string(workDir), basePath)
					_, tryOutErr = os.Stat(tryOutPath)
					if tryOutErr != nil {
						logger.Trace().Err(err).Msgf("joining displayTargetFile: %s to workDir: %s failed. Falling back to returning: %s", displayTargetFile, workDir, displayTargetFile)
						tryOutPath = displayTargetFile // we give up and return the display target file
					}
				}
			}
		}
		isAbs = filepath.IsAbs(tryOutPath)
		if !isAbs {
			logger.Error().Msgf("couldn't determine absolute file path for: %s", scanResult.DisplayTargetFile)
			return ""
		}
		return types.FilePath(tryOutPath)
	}

	// it's relative, we can now just return it!
	joinedRelative := filepath.Join(string(workDir), relative)
	_, statErr := os.Stat(joinedRelative)
	if statErr != nil {
		abs, err := filepath.Abs(joinedRelative)
		if err != nil {
			return ""
		}

		_, statErr = os.Stat(abs)
		if statErr != nil {
			return ""
		}

		return types.FilePath(abs)
	}
	// we really can't figure it out, we return empty
	return ""
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
func (cliScanner *CLIScanner) handleError(path types.FilePath, err error, res []byte, cmd []string) (bool, error) {
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

func determineTargetFile(displayTargetFile string) string {
	fileName := filepath.Base(displayTargetFile)
	manifestFileName := lockFilesToManifestMap[fileName]
	if manifestFileName == "" {
		return displayTargetFile
	}
	return strings.Replace(displayTargetFile, fileName, manifestFileName, 1)
}

func (cliScanner *CLIScanner) retrieveIssues(res *scanResult, workDir types.FilePath, targetFilePath types.FilePath, fileContent []byte) []types.Issue {
	// we are updating the cli scanner maps/attributes in parallel, so we need to lock
	cliScanner.mutex.Lock()
	defer cliScanner.mutex.Unlock()
	issues := convertScanResultToIssues(cliScanner.config, res, workDir, targetFilePath, fileContent, cliScanner.learnService, cliScanner.errorReporter, cliScanner.packageIssueCache)

	// repopulate
	cliScanner.addVulnerabilityCountsToCache(issues)

	return issues
}

// scheduleRefreshScan Schedules new scan after refreshScanWaitDuration once existing OSS results might be stale.
// The timer is reset if a new scan is scheduled before the previous one is executed.
// Canceling the context will stop the timer and abort the scheduled scan.
func (cliScanner *CLIScanner) scheduleRefreshScan(ctx context.Context, path types.FilePath) {
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
			_, _ = cliScanner.Scan(span.Context(), path, "", nil)
		case <-ctx.Done():
			logger.Info().Msg("Scheduled scan canceled")
			timer.Stop()
			return
		}
	}()
}
