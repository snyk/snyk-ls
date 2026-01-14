/*
 * © 2022-2024 Snyk Limited
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

// Package code provides Snyk Code (SAST) scanning functionality.
package code

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/erni27/imcache"
	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"

	codeClient "github.com/snyk/code-client-go"
	codeClientConfig "github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	codeClientObservability "github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	gafUtils "github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

type ScanStatus struct {
	// finished channel is closed once the scan has finished
	finished chan bool

	// isRunning is true when the scan is either running or waiting to run, and changed to false when it's done
	isRunning bool

	// isPending is true when the scan is currently waiting for a previous scan to finish
	isPending bool
}

func NewScanStatus() *ScanStatus {
	return &ScanStatus{
		finished:  make(chan bool),
		isRunning: false,
		isPending: false,
	}
}

type Scanner struct {
	SnykApiClient      snyk_api.SnykApiClient
	errorReporter      codeClientObservability.ErrorReporter
	bundleHashesMutex  sync.RWMutex
	changedFilesMutex  sync.RWMutex
	scanStatusMutex    sync.RWMutex
	runningScans       map[types.FilePath]*ScanStatus
	changedPaths       map[types.FilePath]map[types.FilePath]bool // tracks files that were changed since the last scan per workspace folder
	learnService       learn.Service
	featureFlagService featureflag.Service
	fileFilters        *xsync.MapOf[string, *gafUtils.FileFilter]
	notifier           notification.Notifier

	// global map to store last used bundle hashes for each workspace folder
	// these are needed when we want to retrieve auto-fixes for a previously
	// analyzed folder
	bundleHashes map[types.FilePath]string
	// this is the local scanner issue cache. In the future, it should be used as source of truth for the issues
	// the cache in workspace/folder should just delegate to this cache
	issueCache          *imcache.Cache[types.FilePath, []types.Issue]
	cacheRemovalHandler func(path types.FilePath)
	Instrumentor        performance.Instrumentor
	C                   *config.Config
	codeInstrumentor    codeClientObservability.Instrumentor
	codeErrorReporter   codeClientObservability.ErrorReporter
	codeScanner         func(sc *Scanner, folderConfig *types.FolderConfig) (codeClient.CodeScanner, error)
}

func (sc *Scanner) BundleHashes() map[types.FilePath]string {
	sc.bundleHashesMutex.RLock()
	defer sc.bundleHashesMutex.RUnlock()
	return sc.bundleHashes
}

func (sc *Scanner) AddBundleHash(key types.FilePath, value string) {
	sc.bundleHashesMutex.Lock()
	defer sc.bundleHashesMutex.Unlock()
	if sc.bundleHashes == nil {
		sc.bundleHashes = make(map[types.FilePath]string)
	}
	sc.bundleHashes[key] = value
}

func New(c *config.Config, instrumentor performance.Instrumentor, apiClient snyk_api.SnykApiClient, reporter codeClientObservability.ErrorReporter, learnService learn.Service, featureFlagService featureflag.Service, notifier notification.Notifier, codeInstrumentor codeClientObservability.Instrumentor, codeErrorReporter codeClientObservability.ErrorReporter, codeScanner func(sc *Scanner, folderConfig *types.FolderConfig) (codeClient.CodeScanner, error)) *Scanner {
	sc := &Scanner{
		SnykApiClient:      apiClient,
		errorReporter:      reporter,
		runningScans:       map[types.FilePath]*ScanStatus{},
		changedPaths:       map[types.FilePath]map[types.FilePath]bool{},
		fileFilters:        xsync.NewMapOf[*gafUtils.FileFilter](),
		learnService:       learnService,
		featureFlagService: featureFlagService,
		notifier:           notifier,
		bundleHashes:       map[types.FilePath]string{},
		Instrumentor:       instrumentor,
		C:                  c,
		codeInstrumentor:   codeInstrumentor,
		codeErrorReporter:  codeErrorReporter,
		codeScanner:        codeScanner,
	}
	sc.issueCache = imcache.New[types.FilePath, []types.Issue](
		imcache.WithDefaultExpirationOption[types.FilePath, []types.Issue](time.Hour * 12),
	)
	return sc
}

func (sc *Scanner) IsEnabled() bool {
	return sc.C.IsSnykCodeEnabled() ||
		sc.C.IsSnykCodeSecurityEnabled()
}

func (sc *Scanner) Product() product.Product {
	return product.ProductCode
}

func (sc *Scanner) SupportedCommands() []types.CommandName {
	return []types.CommandName{types.NavigateToRangeCommand}
}

func (sc *Scanner) Scan(ctx context.Context, path types.FilePath, folderConfig *types.FolderConfig) (issues []types.Issue, err error) {
	// Log scan type and paths
	scanType := "WorkingDirectory"
	if deltaScanType, ok := ctx2.DeltaScanTypeFromContext(ctx); ok {
		scanType = deltaScanType.String()
	}
	workspaceFolder := folderConfig.FolderPath
	logger := sc.C.Logger().With().
		Str("method", "code.Scan").
		Str("path", string(path)).
		Str("workspaceFolder", string(workspaceFolder)).
		Str("scanType", scanType).
		Logger()

	logger.Debug().Msg("Code scanner: starting scan")

	if !sc.C.NonEmptyToken() {
		logger.Info().Msg("not authenticated, not scanning")
		return issues, err
	}

	if folderConfig == nil || folderConfig.SastSettings == nil {
		logger.Error().Str("workspaceFolder", string(workspaceFolder)).Msg("folder config or SAST settings is nil")
		return issues, errors.New("folder config or SAST settings not available")
	}

	sastResponse := folderConfig.SastSettings

	if !sastResponse.SastEnabled {
		return issues, errors.New(utils.ErrSnykCodeNotEnabled)
	}

	if isLocalEngineEnabled(sastResponse) {
		updateCodeApiLocalEngine(sc.C, sastResponse)
	}

	// Determine if this is a full folder scan (path equals workspaceFolder or is a directory)
	// vs an incremental file scan (path is a specific file)
	isFolderScan := path == workspaceFolder || uri.IsDirectory(path)

	sc.changedFilesMutex.Lock()
	if sc.changedPaths[workspaceFolder] == nil {
		sc.changedPaths[workspaceFolder] = map[types.FilePath]bool{}
	}
	// Only track specific file paths for incremental scans, not folder paths
	if !isFolderScan {
		sc.changedPaths[workspaceFolder][path] = true
	}
	sc.changedFilesMutex.Unlock()

	// When starting a scan for a workspace folder that's already scanned, the new scan will wait for the previous scan
	// to finish before starting.
	// When there's already a scan waiting, the function returns immediately with empty results.
	scanStatus := NewScanStatus()
	isAlreadyWaiting := sc.waitForScanToFinish(scanStatus, workspaceFolder)
	if isAlreadyWaiting {
		return []types.Issue{}, nil // Returning an empty slice implies that no issues were found
	}
	defer func() {
		sc.scanStatusMutex.Lock()
		scanStatus.isRunning = false
		close(scanStatus.finished)
		sc.scanStatusMutex.Unlock()
	}()

	// For incremental file scans, only proceed if there are changed paths to scan.
	// For folder scans, always proceed to scan all files in the folder.
	var filesToBeScanned map[types.FilePath]bool
	if !isFolderScan {
		sc.changedFilesMutex.Lock()
		if len(sc.changedPaths[workspaceFolder]) <= 0 {
			sc.changedFilesMutex.Unlock()
			return []types.Issue{}, nil
		}
		filesToBeScanned = sc.getFilesToBeScanned(workspaceFolder)
		sc.changedFilesMutex.Unlock()
	}

	results, err := internalScan(ctx, sc, workspaceFolder, folderConfig, logger, filesToBeScanned)
	if err != nil {
		return nil, err
	}

	// Populate HTML template
	sc.enhanceIssuesDetails(results)

	sc.removeFromCache(filesToBeScanned)
	sc.addToCache(results)
	return results, err
}

func internalScan(ctx context.Context, sc *Scanner, folderPath types.FilePath, folderConfig *types.FolderConfig, logger zerolog.Logger, filesToBeScanned map[types.FilePath]bool) (results []types.Issue, err error) {
	span := sc.Instrumentor.StartSpan(ctx, "code.ScanWorkspace")
	defer sc.Instrumentor.Finish(span)
	ctx, cancel := context.WithCancel(span.Context())
	defer cancel()

	// Enrich logger with scan type
	scanType := "WorkingDirectory"
	if deltaScanType, ok := ctx2.DeltaScanTypeFromContext(ctx); ok {
		scanType = deltaScanType.String()
	}
	logger = logger.With().Str("scanType", scanType).Logger()
	logger.Debug().
		Int("fileCount", len(filesToBeScanned)).
		Msg("Code scanner: files to be scanned")

	t := progress.NewTracker(true)
	// monitor external tracker & context cancellations
	go func() { t.CancelOrDone(cancel, ctx.Done()) }()

	t.BeginWithMessage(string("Snyk Code: scanning "+folderPath), "starting scan")
	defer t.EndWithMessage(string("Snyk Code: scan of " + folderPath + " done"))

	fileFilter, _ := sc.fileFilters.Load(string(folderPath))
	if fileFilter == nil {
		fileFilter = gafUtils.NewFileFilter(string(folderPath), &logger)
		sc.fileFilters.Store(string(folderPath), fileFilter)
	}

	rules, err := fileFilter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
	if err != nil {
		return nil, err
	}

	defaultGlobs := []string{"**/.git/**", "**/.svn/**", "**/.hg/**", "**/.bzr/**", "**/.DS_Store/**"}
	rules = append(defaultGlobs, rules...)

	files := fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), rules)

	if t.IsCanceled() || ctx.Err() != nil {
		progress.Cancel(t.GetToken())
		return results, err
	}

	codeConsistentIgnoresEnabled := sc.featureFlagService.GetFromFolderConfig(folderPath, featureflag.SnykCodeConsistentIgnores)
	results, err = sc.UploadAndAnalyze(ctx, folderPath, folderConfig, files, filesToBeScanned, codeConsistentIgnoresEnabled, t)

	return results, err
}

// Populate HTML template
func (sc *Scanner) enhanceIssuesDetails(issues []types.Issue) {
	logger := sc.C.Logger().With().Str("method", "issue_enhancer.enhanceIssuesDetails").Logger()

	for i := range issues {
		issue := issues[i]
		issueData, ok := issue.GetAdditionalData().(snyk.CodeIssueData)
		if !ok {
			logger.Error().Msg("Failed to fetch additional data")
			continue
		}

		lesson, err := sc.learnService.GetLesson(issue.GetEcosystem(), issue.GetID(), issue.GetCWEs(), issue.GetCVEs(), issue.GetIssueType())
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to get lesson")
			sc.errorReporter.CaptureError(err, codeClientObservability.ErrorReporterOptions{ErrorDiagnosticPath: ""})
		} else if lesson != nil && lesson.Url != "" {
			issue.SetLessonUrl(lesson.Url)
		}
		issue.SetAdditionalData(issueData)
	}
}

// getFilesToBeScanned returns a map of files that need to be scanned and removes them from the changedPaths set.
// This function also analyzes interfile dependencies, taking into account the dataflow between files.
func (sc *Scanner) getFilesToBeScanned(folderPath types.FilePath) map[types.FilePath]bool {
	logger := config.CurrentConfig().Logger().With().Str("method", "code.getFilesToBeScanned").Logger()
	changedFiles := make(map[types.FilePath]bool)
	for changedPath := range sc.changedPaths[folderPath] {
		if uri.IsDirectory(changedPath) {
			logger.Debug().Any("path", changedPath).Msg("skipping directory")
			continue
		}
		changedFiles[changedPath] = true
		delete(sc.changedPaths[folderPath], changedPath)
		logger.Debug().Any("path", changedPath).Msg("added to changed files")

		// determine interfile dependencies
		cache := sc.issueCache.GetAll()
		for filePath, fileIssues := range cache {
			referencedFiles := getReferencedFiles(fileIssues)
			for _, referencedFile := range referencedFiles {
				if referencedFile == changedPath {
					changedFiles[filePath] = true
					logger.Debug().Any("path", filePath).Any("referencedFile", referencedFile).Msg("added to changed files")
				}
			}
		}
	}
	return changedFiles
}

func getReferencedFiles(issues []types.Issue) []types.FilePath {
	var referencedFiles []types.FilePath
	for _, issue := range issues {
		if issue.GetAdditionalData() == nil {
			continue
		}
		codeIssueData, ok := issue.GetAdditionalData().(snyk.CodeIssueData)
		if !ok {
			continue
		}
		for _, dataFlow := range codeIssueData.DataFlow {
			referencedFiles = append(referencedFiles, dataFlow.FilePath)
		}
	}
	return referencedFiles
}

func (sc *Scanner) waitForScanToFinish(scanStatus *ScanStatus, folderPath types.FilePath) bool {
	waitForPreviousScan := false
	scanStatus.isRunning = true
	sc.scanStatusMutex.Lock()
	previousScanStatus, wasFound := sc.runningScans[folderPath]
	if wasFound && previousScanStatus.isRunning {
		if previousScanStatus.isPending {
			sc.scanStatusMutex.Unlock()
			return true
		}

		waitForPreviousScan = true
		scanStatus.isPending = true
	}

	sc.runningScans[folderPath] = scanStatus
	sc.scanStatusMutex.Unlock()
	if waitForPreviousScan {
		<-previousScanStatus.finished // Block here until previous scan is finished

		// Setting isPending = false allows for future scans to wait for the current
		// scan to finish, instead of returning immediately
		sc.scanStatusMutex.Lock()
		scanStatus.isPending = false
		sc.scanStatusMutex.Unlock()
	}
	return false
}

func (sc *Scanner) UploadAndAnalyze(ctx context.Context, path types.FilePath, folderConfig *types.FolderConfig, files <-chan string, changedFiles map[types.FilePath]bool, codeConsistentIgnores bool, t *progress.Tracker) (issues []types.Issue, err error) {
	method := "code.UploadAndAnalyze"
	logger := sc.C.Logger().With().Str("method", method).Logger()

	if ctx.Err() != nil {
		progress.Cancel(t.GetToken())
		logger.Info().Msg("Canceling Code scanner received cancellation signal")
		return issues, nil
	}
	span := sc.Instrumentor.StartSpan(ctx, method)
	defer sc.Instrumentor.Finish(span)

	requestId := span.GetTraceId() // use span trace id as code-request-id
	logger.Info().Str("requestId", requestId).Msg("Starting Code analysis.")

	target, err := scan.NewRepositoryTarget(string(path))
	if err != nil {
		logger.Warn().Msg("could not determine repository URL (target)")
	}

	// convert changedFiles to map[string]bool
	stringChangedFiles := make(map[string]bool)
	for k, v := range changedFiles {
		stringChangedFiles[string(k)] = v
	}

	// Create a new code scanner with Organization populated from folder configuration
	newCodeScanner, err := sc.codeScanner(sc, folderConfig)
	if err != nil {
		return []types.Issue{}, fmt.Errorf("failed to create code scanner: %w", err)
	}

	var sarifResponse *sarif.SarifResponse
	var bundleHash string
	if codeConsistentIgnores {
		sarifResponse, bundleHash, err = newCodeScanner.UploadAndAnalyze(ctx, requestId, target, files, stringChangedFiles)
	} else {
		shardKey := getShardKey(path, sc.C.Token())

		// We listen for updates from the codeScanner on a channel. The codeScanner will close the channel
		statusChannel := make(chan scan.LegacyScanStatus)

		go func() {
			for status := range statusChannel {
				t.ReportWithMessage(status.Percentage, status.Message)
			}
		}()

		sarifResponse, bundleHash, err = newCodeScanner.UploadAndAnalyzeLegacy(ctx, requestId, target, shardKey, files, stringChangedFiles, statusChannel)
	}

	if err != nil || ctx.Err() != nil {
		return []types.Issue{}, err
	}

	if sarifResponse == nil {
		logger.Info().Str("requestId", requestId).Msg("Sarif is nil")
		return []types.Issue{}, nil
	} else {
		logger.Debug().
			Str("method", method).
			Str("status", sarifResponse.Status).
			Float64("progress", sarifResponse.Progress).
			Int("fetchingCodeTime", sarifResponse.Timing.FetchingCode).
			Int("analysisTime", sarifResponse.Timing.Analysis).
			Int("filesAnalyzed", len(sarifResponse.Coverage)).
			Msg("Received response summary")
	}

	sc.bundleHashesMutex.Lock()
	sc.bundleHashes[path] = bundleHash
	sc.bundleHashesMutex.Unlock()

	converter := SarifConverter{sarif: *sarifResponse, logger: &logger, hoverVerbosity: sc.C.HoverVerbosity()}
	issues, err = converter.toIssues(path)
	if err != nil {
		return []types.Issue{}, err
	}
	issueEnhancer := newIssueEnhancer(
		sc.Instrumentor,
		sc.errorReporter,
		sc.notifier,
		sc.learnService,
		requestId,
		path,
		sc.C,
		folderConfig,
	)
	issueEnhancer.addIssueActions(ctx, issues)

	return issues, nil
}

// createCodeConfig creates a new codeConfig with Organization populated from folder configuration
// and delegates other values to the language server config
func (sc *Scanner) createCodeConfig(folderConfig *types.FolderConfig) (codeClientConfig.Config, error) {
	logger := sc.C.Logger().With().Str("method", "code.createCodeConfig").Logger()

	if folderConfig == nil {
		return nil, fmt.Errorf("folder config is required to create code config")
	}

	// TODO - we are being inefficient and re-fetching the folder config in the function calls instead of passing it in
	workspaceFolderPath := folderConfig.FolderPath
	organization := sc.C.FolderOrganization(workspaceFolderPath)
	if organization == "" {
		return nil, fmt.Errorf("no organization found for workspace folder %s", workspaceFolderPath)
	}

	// Ensure the organization is a UUID, not a slug
	// code-client-go expects a UUID and will panic if given a slug
	orgUUID, err := sc.C.ResolveOrgToUUID(organization)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve organization to UUID for workspace folder %s: %w", workspaceFolderPath, err)
	}

	codeApiURL, err := GetCodeApiUrlForFolder(sc.C, workspaceFolderPath)
	if err != nil {
		msg := fmt.Sprintf("Failed to get code api url for workspace folder %s", workspaceFolderPath)
		logger.Error().Msg(msg)
		return nil, err
	}

	// Create a lazy config that delegates to the language server config
	return &CodeConfig{
		orgForFolder: orgUUID,
		lsConfig:     sc.C,
		codeApiUrl:   codeApiURL,
	}, nil
}

// CreateCodeScanner creates a real code scanner with Organization populated from folder configuration
func CreateCodeScanner(scanner *Scanner, folderConfig *types.FolderConfig) (codeClient.CodeScanner, error) {
	// Create a new codeConfig with Organization populated from folder configuration
	codeConfig, err := scanner.createCodeConfig(folderConfig)
	if err != nil {
		return nil, err
	}

	// Create a new HTTP client
	httpClient := codeClientHTTP.NewHTTPClient(
		scanner.C.Engine().GetNetworkAccess().GetHttpClient,
		codeClientHTTP.WithLogger(scanner.C.Engine().GetLogger()),
		codeClientHTTP.WithInstrumentor(scanner.codeInstrumentor),
		codeClientHTTP.WithErrorReporter(scanner.codeErrorReporter),
	)

	// Create and return a new code scanner with the custom config
	return codeClient.NewCodeScanner(
		codeConfig,
		httpClient,
		codeClient.WithTrackerFactory(NewCodeTrackerFactory()),
		codeClient.WithLogger(scanner.C.Engine().GetLogger()),
		codeClient.WithInstrumentor(scanner.codeInstrumentor),
		codeClient.WithErrorReporter(scanner.codeErrorReporter),
	), nil
}
