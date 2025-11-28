package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/sdk"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/scans"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

var (
	allProjectsParamBlacklist = map[string]bool{
		"--file": true,
	}

	// Make sure CLIScanner implements the desired interfaces
	_ types.ProductScanner     = (*CLIScanner)(nil)
	_ snyk.InlineValueProvider = (*CLIScanner)(nil)

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
		refreshScanWaitDuration: 6 * time.Hour,
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
	return cliScanner.config.IsSnykSecretsEnabled()
}

func (cliScanner *CLIScanner) Product() product.Product {
	return product.ProductSecrets
}

func (cliScanner *CLIScanner) Scan(ctx context.Context, path types.FilePath, workDir types.FilePath, folderConfig *types.FolderConfig) (issues []types.Issue, err error) {
	logger := cliScanner.getLogger(ctx)
	ctx = cliScanner.enrichContext(ctx)

	// Add path to context so it can be used by scheduled scans
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, workDir, path)

	if folderConfig != nil {
		deps, found := ctx2.DependenciesFromContext(ctx)
		if !found {
			deps = map[string]any{}
		}
		deps[ctx2.DepFolderConfig] = folderConfig
		ctx = ctx2.NewContextWithDependencies(ctx, deps)
	}

	if !cliScanner.config.NonEmptyToken() {
		logger.Info().Msg("not authenticated, not scanning")
		return issues, err
	}
	cliPathScan := cliScanner.isSupported(path)
	if !cliPathScan {
		logger.Debug().Msgf("Secrets Scan not supported for %s", path)
		return issues, nil
	}
	return cliScanner.scanInternal(ctx, cliScanner.prepareScanCommand)
}

func (cliScanner *CLIScanner) getLogger(ctx context.Context) zerolog.Logger {
	givenLogger := ctx2.LoggerFromContext(ctx)
	if givenLogger == nil {
		givenLogger = cliScanner.config.Logger()
	}
	logger := givenLogger.With().Str("method", "CLIScanner.scan").Logger()
	return logger
}

func (cliScanner *CLIScanner) enrichContext(ctx context.Context) context.Context {
	dependenciesFromContext, found := ctx2.DependenciesFromContext(ctx)
	if !found {
		dependenciesFromContext = map[string]any{}
	}
	dependenciesFromContext[ctx2.DepLearnService] = cliScanner.learnService
	dependenciesFromContext[ctx2.DepErrorReporter] = cliScanner.errorReporter
	dependenciesFromContext[ctx2.DepCLIExecutor] = cliScanner.cli
	dependenciesFromContext[ctx2.DepConfig] = cliScanner.config

	return ctx2.NewContextWithDependencies(ctx, dependenciesFromContext)
}

func (cliScanner *CLIScanner) isSupported(path types.FilePath) bool {
	return uri.IsDirectory(path) || cliScanner.supportedFiles[filepath.Base(string(path))]
}

func (cliScanner *CLIScanner) prepareScanCommand(args []string, parameterBlacklist map[string]bool, path types.FilePath, folderConfig *types.FolderConfig) []string {
	allProjectsParamAllowed := true
	allProjectsParam := "--all-projects"

	cmd := cliScanner.cli.ExpandParametersFromConfig([]string{
		cliScanner.config.CliSettings().Path(),
		"test",
		"--json",
	})

	args = cliScanner.updateArgs(path, args, folderConfig)
	args = append(args, cliScanner.config.CliSettings().AdditionalOssParameters...) // TODO check for secrets.

	processedArgs := []string{}
	// now add all additional parameters, skipping blacklisted ones
	for _, parameter := range args {
		if storedconfig.SliceContainsParam(cmd, parameter) {
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

	return cmd
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
			isDuplicateParam := storedconfig.SliceContainsParam(commandLineArgs, parameter)
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

func (cliScanner *CLIScanner) unmarshallAndRetrieveAnalysis(
	ctx context.Context,
	scanOutput any,
	workDir types.FilePath,
	path types.FilePath,
	format string,
) (issues []types.Issue) {
	issues, err := ProcessScanResults(
		ctx,
		scanOutput,
	)

	if err != nil {
		cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		return []types.Issue{}
	}

	// Add vulnerability counts to cache (CLIScanner-specific behavior)
	if len(issues) > 0 {
		cliScanner.mutex.Lock()
		cliScanner.addVulnerabilityCountsToCache(issues)
		cliScanner.mutex.Unlock()
	}

	return issues
}

// scheduleRefreshScan Schedules new scan after refreshScanWaitDuration once existing Secrets results might be stale.
// The timer is reset if a new scan is scheduled before the previous one is executed.
// Canceling the context will stop the timer and abort the scheduled scan.
func (cliScanner *CLIScanner) scheduleRefreshScan(ctx context.Context, path types.FilePath) {
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
			if !cliScanner.IsEnabled() {
				logger.Info().Msg("Secrets scan is disabled, skipping scheduled scan")
				return
			}

			if newCtx.Err() != nil {
				logger.Info().Msg("Scheduled scan canceled")
				return
			}

			span := cliScanner.instrumentor.NewTransaction(context.WithValue(newCtx, cliScanner.Product(), cliScanner),
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

func determineTargetFile(displayTargetFile string) string {
	fileName := filepath.Base(displayTargetFile)
	manifestFileName := lockFilesToManifestMap[fileName]
	if manifestFileName == "" {
		return displayTargetFile
	}
	return strings.Replace(displayTargetFile, fileName, manifestFileName, 1)
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

func (cliScanner *CLIScanner) scanInternal(
	ctx context.Context,
	commandFunc func(args []string, parameterBlacklist map[string]bool, path types.FilePath, folderConfig *types.FolderConfig) []string,
) ([]types.Issue, error) {
	method := "cliScanner.Scan"
	logger := cliScanner.getLogger(ctx).With().Str("method", method).Logger()

	// get data from context
	path := ctx2.FilePathFromContext(ctx)
	deps, found := ctx2.DependenciesFromContext(ctx)
	if !found {
		const msg = "dependencies not found in context"
		logger.Error().Msg(msg)
		return []types.Issue{}, errors.New(msg)
	}

	folderConfig, ok := deps[ctx2.DepFolderConfig].(*types.FolderConfig)
	if !ok {
		const msg = "folderConfig not found in context"
		logger.Error().Msg(msg)
		return []types.Issue{}, errors.New(msg)
	}

	// now start the scanning
	s := cliScanner.instrumentor.StartSpan(ctx, method)
	defer cliScanner.instrumentor.Finish(s)
	logger.Debug().Msg("started.")
	defer logger.Debug().Msg("done.")

	if ctx.Err() != nil {
		logger.Debug().Msg("Canceling Secrets scan - Secrets scanner received cancellation signal")
		return []types.Issue{}, nil
	}

	// save parent context for scheduling refresh scan
	parentCtx := s.Context()

	// create cancelable progress tracker
	ctx, cancel := context.WithCancel(s.Context())
	defer cancel()

	p := progress.NewTracker(true)
	go func() { p.CancelOrDone(cancel, ctx.Done()) }()
	p.BeginUnquantifiableLength("Scanning for Snyk Open Source issues", string(path))
	defer p.EndWithMessage("Snyk Open Source scan completed.")

	// normalize & determine paths
	filePath, err := filepath.Abs(string(path))
	if err != nil {
		logger.Err(err).Msg("Error while extracting file absolutePath")
	}

	var workDir types.FilePath
	if uri.IsDirectory(path) {
		workDir = path
	} else {
		workDir = types.FilePath(filepath.Dir(filePath))
	}

	// cancel running scans on same workdir
	cliScanner.mutex.Lock()
	i := cliScanner.scanCount
	previousScan, wasFound := cliScanner.runningScans[workDir]
	if wasFound && !previousScan.IsDone() {
		previousScan.CancelScan()
	}
	newScan := scans.NewScanProgress()
	go newScan.Listen(cancel, i)
	cliScanner.scanCount++
	cliScanner.runningScans[workDir] = newScan
	cliScanner.mutex.Unlock()

	cmd := commandFunc([]string{string(workDir)}, map[string]bool{"": true}, workDir, folderConfig)

	// check if scan was canceled
	if ctx.Err() != nil {
		logger.Debug().Msg("Canceling Secrets scan - Secrets scanner received cancellation signal")
		return []types.Issue{}, nil
	}

	// do actual scan
	var output any
	logger.Info().Msg("🐉🪰using new ostest scanner")
	output, err = cliScanner.ostestScan(ctx, path, cmd, workDir)
	if err != nil {
		logger.Err(err).Msg("Error while scanning for Secrets issues")
		return []types.Issue{}, err
	}

	// convert scan results into issues
	issues := cliScanner.unmarshallAndRetrieveAnalysis(ctx, output, workDir, path, cliScanner.config.Format())

	// mark scan done
	cliScanner.mutex.Lock()
	logger.Debug().Msgf("Scan %v is done", i)
	newScan.SetDone()
	cliScanner.mutex.Unlock()

	// scan again after cache expiry
	if issues != nil {
		cliScanner.scheduleRefreshScan(parentCtx, path)
	}
	return issues, nil
}
