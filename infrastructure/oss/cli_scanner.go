/*
 * © 2023-2026 Snyk Limited
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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/subosito/gotenv"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/issuecache"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/scans"
	"github.com/snyk/snyk-ls/internal/sdk"
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
		"uv.lock":           "pyproject.toml",
	}

	// see https://github.com/snyk/cli/blob/765e53a67ea1cbad79c2ee8c436e5e5816003744/src/cli/main.ts#L388-L397
	allProjectsParamBlacklist = map[string]bool{
		"--file":             true,
		"--package-manager":  true,
		"--project-name":     true,
		"--yarn-workspaces":  true,
		"--docker":           true,
		"--all-sub-projects": true,
	}

	// Make sure CLIScanner implements the desired interfaces
	_ types.ProductScanner     = (*CLIScanner)(nil)
	_ snyk.InlineValueProvider = (*CLIScanner)(nil)
	_ snyk.CacheProvider       = (*CLIScanner)(nil)
)

type CLIScanner struct {
	*issuecache.IssueCache
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
	engine                  workflow.Engine
	configResolver          types.ConfigResolverInterface
}

func NewCLIScanner(engine workflow.Engine, instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, cli cli.Executor, learnService learn.Service, notifier noti.Notifier, configResolver types.ConfigResolverInterface) types.ProductScanner {
	scanner := CLIScanner{
		IssueCache:              issuecache.NewIssueCacheForProduct(engine, product.ProductOpenSource),
		instrumentor:            instrumentor,
		errorReporter:           errorReporter,
		cli:                     cli,
		mutex:                   &sync.RWMutex{},
		inlineValueMutex:        &sync.RWMutex{},
		packageScanMutex:        &sync.Mutex{},
		scheduledScanMtx:        &sync.Mutex{},
		runningScans:            map[types.FilePath]*scans.ScanProgress{},
		refreshScanWaitDuration: 6 * time.Hour,
		scanCount:               1,
		learnService:            learnService,
		notifier:                notifier,
		inlineValues:            make(inlineValueMap),
		engine:                  engine,
		configResolver:          configResolver,
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
			"uv.lock":                 true,
			"pyproject.toml":          true,
		},
	}
	return &scanner
}

func (cliScanner *CLIScanner) getConfigResolver(ctx context.Context) types.ConfigResolverInterface {
	if r, ok := ctx2.ConfigResolverFromContext(ctx); ok && r != nil {
		return r
	}
	return cliScanner.configResolver
}

func (cliScanner *CLIScanner) IsEnabledForFolder(folderConfig *types.FolderConfig) bool {
	return cliScanner.configResolver.IsProductEnabledForFolder(product.ProductOpenSource, folderConfig)
}

func (cliScanner *CLIScanner) Product() product.Product {
	return product.ProductOpenSource
}

// Scan implements types.ProductScanner.
// For CLI-based scanners, pathToScan is the target file or folder to scan.
func (cliScanner *CLIScanner) Scan(ctx context.Context, pathToScan types.FilePath) (issues []types.Issue, err error) {
	workspaceFolderConfig, ok := ctx2.FolderConfigFromContext(ctx)
	if !ok || workspaceFolderConfig == nil {
		return nil, errors.New("FolderConfig not found in context")
	}

	// Log scan type and paths
	scanType := "WorkingDirectory"
	if deltaScanType, ok := ctx2.DeltaScanTypeFromContext(ctx); ok {
		scanType = deltaScanType.String()
	}
	workspaceFolder := workspaceFolderConfig.FolderPath
	logger := cliScanner.getLogger(ctx).With().
		Str("pathToScan", string(pathToScan)).
		Str("workspaceFolder", string(workspaceFolder)).
		Str("scanType", scanType).
		Logger()

	logger.Debug().Msg("OSS scanner: starting scan")

	// Ensure path is in context for scanInternal (when called directly, e.g. from tests)
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, workspaceFolder, pathToScan)
	ctx = cliScanner.enrichContext(ctx)

	if config.GetToken(cliScanner.engine.GetConfiguration()) == "" {
		logger.Info().Msg("not authenticated, not scanning")
		return issues, err
	}
	cliPathScan := cliScanner.isSupported(pathToScan)
	if !cliPathScan {
		logger.Debug().Msg("OSS scanner: skipping unsupported file/directory")
		return issues, nil
	}
	return cliScanner.scanInternal(ctx, cliScanner.prepareScanCommand)
}

func (cliScanner *CLIScanner) getLogger(ctx context.Context) zerolog.Logger {
	givenLogger := ctx2.LoggerFromContext(ctx)
	if givenLogger == nil {
		givenLogger = cliScanner.engine.GetLogger()
	}
	logger := givenLogger.With().Str("method", "CLIScanner.scan").Logger()
	return logger
}

func (cliScanner *CLIScanner) scanInternal(ctx context.Context, commandFunc func(args []string, parameterBlacklist map[string]bool, path types.FilePath, folderConfig *types.FolderConfig) ([]string, gotenv.Env)) ([]types.Issue, error) {
	method := "cliScanner.Scan"
	logger := cliScanner.getLogger(ctx).With().Str("method", method).Logger()

	// get data from context
	path := ctx2.FilePathFromContext(ctx)
	folderConfig, ok := ctx2.FolderConfigFromContext(ctx)
	if !ok || folderConfig == nil {
		const msg = "FolderConfig not found in context"
		logger.Error().Msg(msg)
		return []types.Issue{}, errors.New(msg)
	}

	// now start the scanning
	s := cliScanner.instrumentor.StartSpan(ctx, method)
	defer cliScanner.instrumentor.Finish(s)
	logger.Debug().Msg("started.")
	defer logger.Debug().Msg("done.")

	if ctx.Err() != nil {
		logger.Debug().Msg("Canceling OSS scan - OSS scanner received cancellation signal")
		return []types.Issue{}, nil
	}

	// save parent context for scheduling refresh scan
	parentCtx := s.Context()

	// create cancelable progress tracker
	ctx, cancel := context.WithCancel(s.Context())
	defer cancel()

	p := progress.NewTracker(true, cliScanner.engine.GetLogger())
	go func() { p.CancelOrDone(cancel, ctx.Done()) }()
	p.BeginUnquantifiableLength("Scanning for Snyk Open Source issues", string(path))
	defer p.EndWithMessage("Snyk Open Source scan completed.")

	// Use workspace folder from folderConfig for CLI execution (org lookup, etc.)
	workspaceFolder := folderConfig.FolderPath

	// cancel running scans on same workspace folder
	cliScanner.mutex.Lock()
	i := cliScanner.scanCount
	previousScan, wasFound := cliScanner.runningScans[workspaceFolder]
	if wasFound && !previousScan.IsDone() {
		previousScan.CancelScan()
	}
	newScan := scans.NewScanProgressWithLogger(cliScanner.engine.GetLogger())
	go newScan.Listen(ctx, cancel, i)
	defer func() {
		cliScanner.mutex.Lock()
		logger.Debug().Msgf("Scan %v is done", i)
		newScan.SetDone() // Calling SetDone is safe even after cancellation
		cliScanner.mutex.Unlock()
	}()
	cliScanner.scanCount++
	cliScanner.runningScans[workspaceFolder] = newScan
	cliScanner.mutex.Unlock()

	cmd, env := commandFunc([]string{string(workspaceFolder)}, map[string]bool{"": true}, workspaceFolder, folderConfig)

	// check if scan was canceled
	if ctx.Err() != nil {
		logger.Debug().Msg("Canceling OSS scan - OSS scanner received cancellation signal")
		return []types.Issue{}, nil
	}

	// determine which scanner to use, mirroring cli-extension-os-flows ShouldUseLegacyFlow
	useLegacyScan, reason := shouldUseLegacyScan(folderConfig, cmd)

	// do actual scan
	var output any
	var err error
	if useLegacyScan {
		logger.Info().Str("reason", reason).Msg("⚠️ using legacy OSS scanner")

		output, err = cliScanner.legacyScan(ctx, path, cmd, folderConfig, env)
		if err != nil {
			logger.Err(err).Msg("Error while scanning for OSS issues")
			return []types.Issue{}, err
		}
	} else {
		logger.Info().Str("reason", reason).Msg("🐉🪰 using new ostest scanner")
		output, err = cliScanner.ostestScan(ctx, path, cmd, folderConfig, env)
		if err != nil {
			logger.Err(err).Msg("Error while scanning for OSS issues")
			return []types.Issue{}, err
		}
	}

	// convert scan results into issues
	issues := cliScanner.unmarshallAndRetrieveAnalysis(ctx, output, workspaceFolder, path, cliScanner.configResolver.GetString(types.SettingFormat, folderConfig))

	// scan again after cache expiry
	if issues != nil {
		cliScanner.scheduleRefreshScan(parentCtx, path, folderConfig)
	}
	return issues, nil
}

func (cliScanner *CLIScanner) legacyScan(ctx context.Context, pathToScan types.FilePath, cmd []string, folderConfig *types.FolderConfig, env gotenv.Env) ([]byte, error) {
	logger := cliScanner.engine.GetLogger().With().Str("method", "cliScanner.legacyScan").Logger()
	res, scanErr := cliScanner.cli.Execute(ctx, cmd, folderConfig.FolderPath, env)
	noCancellation := ctx.Err() == nil
	if scanErr != nil {
		if noCancellation {
			cliFailed, handledErr := cliScanner.handleError(pathToScan, scanErr, res, cmd)
			if cliFailed {
				return nil, handledErr
			}
		} else { // If scan was canceled, return empty results
			logger.Info().Msg("OSS scan was canceled, returning empty issues")
			return []byte{}, nil
		}
	}
	return res, nil
}

func (cliScanner *CLIScanner) updateArgs(workDir types.FilePath, commandLineArgs []string, folderConfig *types.FolderConfig) ([]string, gotenv.Env) {
	if folderConfig == nil {
		folderConfig = config.GetFolderConfigFromEngine(cliScanner.engine, cliScanner.configResolver, workDir, cliScanner.engine.GetLogger())
	}
	folderConfigArgs := cliScanner.configResolver.GetStringSlice(types.SettingAdditionalParameters, folderConfig)

	// this asks the client for the current SDK and blocks on it
	additionalParameters, env := cliScanner.updateSDKs(folderConfig.FolderPath)
	// process folder config additional env
	if len(folderConfigArgs) > 0 {
		additionalParameters = append(additionalParameters, folderConfigArgs...)
	}

	if len(additionalParameters) > 0 {
		for _, parameter := range additionalParameters {
			// if the sdk needs additional parameters, add them (Python plugin, I look at you. Yes, you)
			// the given parameters take precedence, meaning, a given python configuration will overrule
			// the automatically determined config
			isDuplicateParam := folderconfig.SliceContainsParam(commandLineArgs, parameter)
			if !isDuplicateParam {
				commandLineArgs = append(commandLineArgs, parameter)
			}
		}
	}
	return commandLineArgs, env
}

// updateSDKs asks the client for the current SDK and blocks on it
// returns additional parameters for the given SDK
func (cliScanner *CLIScanner) updateSDKs(workDir types.FilePath) ([]string, gotenv.Env) {
	logger := cliScanner.engine.GetLogger().With().Str("method", "updateSDKs").Logger()
	sdkChan := make(chan []types.LsSdk)
	getSdk := types.GetSdk{FolderPath: string(workDir), Result: sdkChan}
	logger.Debug().Msg("asking IDE for SDKS")
	cliScanner.notifier.Send(getSdk)
	// wait for sdk info
	sdks := <-sdkChan
	logger.Debug().Msg("received SDKs")
	return sdk.UpdateEnvironmentAndReturnAdditionalParams(cliScanner.engine, cliScanner.configResolver, cliScanner.engine.GetLogger(), sdks)
}

func (cliScanner *CLIScanner) prepareScanCommand(args []string, parameterBlacklist map[string]bool, path types.FilePath, folderConfig *types.FolderConfig) ([]string, gotenv.Env) {
	allProjectsParamAllowed := true
	allProjectsParam := "--all-projects"

	cliPath := cliScanner.configResolver.GetString(types.SettingCliPath, nil)
	if cliPath != "" {
		cliPath = filepath.Clean(cliPath)
	}
	cmd := []string{
		cliPath,
		"test",
		"--json",
	}

	cmd = cliScanner.cli.ExpandParametersFromConfig(cmd, folderConfig)

	args, env := cliScanner.updateArgs(path, args, folderConfig)
	if params := cliScanner.configResolver.GetStringSlice(types.SettingCliAdditionalOssParameters, folderConfig); len(params) > 0 {
		args = append(args, params...)
	}

	processedArgs := []string{}
	// now add all additional parameters, skipping blacklisted ones
	for _, parameter := range args {
		if folderconfig.SliceContainsParam(cmd, parameter) {
			continue
		}

		if parameter == allProjectsParam {
			continue
		}

		p := strings.Split(parameter, "=")[0]

		if parameterBlacklist[p] {
			continue
		}

		if allProjectsParamBlacklist[p] {
			allProjectsParamAllowed = false
		}

		processedArgs = append(processedArgs, parameter)
	}

	// only append --all-projects, if it's not on the global blacklist
	// and if there is no other parameter interfering (e.g. --file)
	containsAllProjects := slices.Contains(cmd, allProjectsParam)
	allProjectsParamAllowed = allProjectsParamAllowed && !containsAllProjects && !parameterBlacklist[allProjectsParam]
	if allProjectsParamAllowed {
		cmd = append(cmd, allProjectsParam)
	}

	cmd = append(cmd, processedArgs...)

	return cmd, env
}

func (cliScanner *CLIScanner) isSupported(path types.FilePath) bool {
	return uri.IsDirectory(path) || cliScanner.supportedFiles[filepath.Base(string(path))]
}

func (cliScanner *CLIScanner) unmarshallAndRetrieveAnalysis(
	ctx context.Context,
	scanOutput any,
	workDir types.FilePath,
	path types.FilePath,
	format string,
) (issues []types.Issue) {
	issues, err := ProcessScanResults(ctx, scanOutput, cliScanner.errorReporter, cliScanner.learnService, true, format)

	if err != nil {
		cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		return []types.Issue{}
	}

	// Base/reference scans run against a temp clone; replacing the IssueCache would wipe
	// working-directory issues keyed to the real workspace folder (DelegatingConcurrentScanner
	// runs a Reference OSS scan after the WD scan).
	if deltaType, ok := ctx2.DeltaScanTypeFromContext(ctx); ok && deltaType == ctx2.Reference {
		return issues
	}

	// Replace OSS snapshot for this scan so IssueCache (memory or bolt) stays the single source of truth.
	cliScanner.Clear()
	if len(issues) > 0 {
		cliScanner.AddToCache(issues)
	}

	// Add vulnerability counts to cache (CLIScanner-specific behavior)
	if len(issues) > 0 {
		cliScanner.mutex.Lock()
		cliScanner.addVulnerabilityCountsToCache(issues)
		cliScanner.mutex.Unlock()
	}

	return issues
}

func getAbsTargetFilePath(logger *zerolog.Logger, resultPath, displayTargetFile string, workDir, path types.FilePath) types.FilePath {
	if displayTargetFile == "" && path != "" {
		return path
	}
	newDisplayTargetFile := determineTargetFile(displayTargetFile)

	// if displayTargetFile is an absolute path, no need to do anything more
	isAbs := filepath.IsAbs(newDisplayTargetFile)
	if isAbs {
		return types.FilePath(newDisplayTargetFile)
	}

	relative, err := filepath.Rel(string(workDir), newDisplayTargetFile)
	if err != nil || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		logger.Trace().Err(err).Msgf("path is not relative to %s", workDir)
		// now we try out stuff
		// if displayTargetFile is not relative, let's try to join path with basename
		basePath := filepath.Base(newDisplayTargetFile)
		scanResultPath := resultPath
		tryOutPath := filepath.Join(scanResultPath, newDisplayTargetFile)
		_, tryOutErr := os.Stat(tryOutPath)
		if tryOutErr != nil {
			logger.Trace().Err(err).Msgf("joining displayTargetFile: %s to path: %s failed", newDisplayTargetFile, scanResultPath)
			tryOutPath = filepath.Join(scanResultPath, basePath)
			_, tryOutErr := os.Stat(tryOutPath)
			if tryOutErr != nil {
				logger.Trace().Err(err).Msgf("joining basePath: %s to path: %s failed", basePath, scanResultPath)
				// if that doesn't work, let's try full path and full display target file
				tryOutPath = filepath.Join(string(workDir), newDisplayTargetFile)
				_, tryOutErr = os.Stat(tryOutPath)
				if tryOutErr != nil {
					logger.Trace().Err(err).Msgf("joining displayTargetFile: %s to workDir: %s failed.", newDisplayTargetFile, workDir)
					tryOutPath = filepath.Join(string(workDir), basePath)
					_, tryOutErr = os.Stat(tryOutPath)
					if tryOutErr != nil {
						logger.Trace().Err(err).Msgf("joining displayTargetFile: %s to workDir: %s failed. Falling back to returning: %s", newDisplayTargetFile, workDir, newDisplayTargetFile)
						tryOutPath = newDisplayTargetFile // we give up and return the display target file
					}
				}
			}
		}
		isAbs = filepath.IsAbs(tryOutPath)
		if !isAbs {
			logger.Error().Msgf("couldn't determine absolute file path for: %s", newDisplayTargetFile)
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
	return UnmarshallOssJson(res)
}

// Returns true if CLI run failed, false otherwise
func (cliScanner *CLIScanner) handleError(path types.FilePath, err error, res []byte, cmd []string) (bool, error) {
	cliError := &types.CliError{}
	unmarshalErr := json.Unmarshal(res, cliError)
	if unmarshalErr != nil {
		cliError.ErrorMessage = string(res)
		cliError.Command = fmt.Sprintf("%v", cmd)
	}

	logger := cliScanner.engine.GetLogger().With().Str("method", "cliScanner.Scan").Str("output", cliError.ErrorMessage).Logger()

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

// scheduleRefreshScan Schedules new scan after refreshScanWaitDuration once existing OSS results might be stale.
// The timer is reset if a new scan is scheduled before the previous one is executed.
// Canceling the context will stop the timer and abort the scheduled scan.
func (cliScanner *CLIScanner) scheduleRefreshScan(ctx context.Context, path types.FilePath, folderConfig *types.FolderConfig) {
	logger := cliScanner.getLogger(ctx)
	cliScanner.scheduledScanMtx.Lock()
	if cliScanner.scheduledScan != nil {
		// Cancel previously scheduled scan
		cliScanner.scheduledScan.Stop()
	}

	timer := time.NewTimer(cliScanner.refreshScanWaitDuration)
	cliScanner.scheduledScan = timer
	cliScanner.scheduledScanMtx.Unlock()

	// decouple scheduled scan from session but keep context values
	newCtx := ctx2.Clone(ctx, context.Background())

	go func() {
		select {
		case <-timer.C:
			folderConfig := config.GetUnenrichedFolderConfigFromEngine(cliScanner.engine, cliScanner.configResolver, path, cliScanner.engine.GetLogger())
			if !cliScanner.getConfigResolver(newCtx).IsProductEnabledForFolder(product.ProductOpenSource, folderConfig) {
				logger.Info().Msg("OSS scan is disabled, skipping scheduled scan")
				return
			}

			if newCtx.Err() != nil {
				logger.Info().Msg("Scheduled scan canceled")
				return
			}

			scanCtx := ctx2.NewContextWithFolderConfig(newCtx, folderConfig)
			span := cliScanner.instrumentor.NewTransaction(context.WithValue(scanCtx, cliScanner.Product(), cliScanner),
				string(cliScanner.Product()),
				"cliScanner.scheduleNewScanIn")
			defer cliScanner.instrumentor.Finish(span)

			logger.Info().Msg("Starting scheduled scan")
			_, _ = cliScanner.Scan(span.Context(), path)
		case <-ctx.Done():
			logger.Info().Msg("Scheduled scan canceled")
			timer.Stop()
			return
		}
	}()
}

// legacyOnlyFlags are CLI flags that require routing to the legacy scan path
// because the new ostest workflow does not support them.
var legacyOnlyFlags = map[string]bool{
	"--print-graph":     true,
	"--print-deps":      true,
	"--print-dep-paths": true,
	"--unmanaged":       true,
}

// newFeatureFlags are CLI flags whose presence indicates the scan requires the new ostest workflow.
var newFeatureFlags = map[string]bool{
	"--reachability": true,
	"--sbom":         true,
}

// shouldUseLegacyScan determines whether the scan should use the legacy CLI path.
// This mirrors the routing logic in cli-extension-os-flows ShouldUseLegacyFlow.
// Returns (useLegacy, reason).
func shouldUseLegacyScan(folderConfig *types.FolderConfig, cmd []string) (bool, string) {
	if isForceLegacyCLI() {
		return true, "SNYK_FORCE_LEGACY_CLI env var set"
	}
	if flag := findLegacyOnlyFlag(cmd); flag != "" {
		return true, fmt.Sprintf("legacy-only flag: %s", flag)
	}
	if matchedFeature := findNewFeature(folderConfig, cmd); matchedFeature != "" {
		return false, fmt.Sprintf("new ostest workflow (matched: %s)", matchedFeature)
	}
	return true, "no new features required"
}

func isForceLegacyCLI() bool {
	return os.Getenv("SNYK_FORCE_LEGACY_CLI") != ""
}

// findLegacyOnlyFlag returns the first legacy-only flag found in cmd, or empty string.
func findLegacyOnlyFlag(cmd []string) string {
	for _, arg := range cmd {
		flag := strings.SplitN(arg, "=", 2)[0]
		if legacyOnlyFlags[flag] {
			return flag
		}
	}
	return ""
}

// findNewFeature returns the first feature flag or command arg that requires the new ostest workflow,
// or an empty string if none matched.
func findNewFeature(folderConfig *types.FolderConfig, cmd []string) string {
	if folderConfig == nil {
		return ""
	}

	if folderConfig.GetFeatureFlag(featureflag.UseExperimentalRiskScoreInCLI) {
		return featureflag.UseExperimentalRiskScoreInCLI
	}
	if folderConfig.GetFeatureFlag(featureflag.UseOsTest) {
		return featureflag.UseOsTest
	}

	for _, arg := range cmd {
		flag := strings.SplitN(arg, "=", 2)[0]
		if newFeatureFlags[flag] {
			return flag
		}
	}

	return ""
}

func (cliScanner *CLIScanner) enrichContext(ctx context.Context) context.Context {
	dependenciesFromContext, found := ctx2.DependenciesFromContext(ctx)
	if !found {
		dependenciesFromContext = map[string]any{}
	}
	dependenciesFromContext[ctx2.DepLearnService] = cliScanner.learnService
	dependenciesFromContext[ctx2.DepErrorReporter] = cliScanner.errorReporter
	dependenciesFromContext[ctx2.DepCLIExecutor] = cliScanner.cli
	dependenciesFromContext[ctx2.DepEngine] = cliScanner.engine

	return ctx2.NewContextWithDependencies(ctx, dependenciesFromContext)
}
