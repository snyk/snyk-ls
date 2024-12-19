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

package code

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/erni27/imcache"
	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync"

	codeClient "github.com/snyk/code-client-go"
	codeClientObservability "github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/scan"

	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/filefilter"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
)

var _ types.DeltaScanner = (*Scanner)(nil)

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
	BundleUploader    *BundleUploader
	SnykApiClient     snyk_api.SnykApiClient
	errorReporter     codeClientObservability.ErrorReporter
	bundleHashesMutex sync.RWMutex
	changedFilesMutex sync.RWMutex
	scanStatusMutex   sync.RWMutex
	runningScans      map[string]*ScanStatus
	changedPaths      map[string]map[string]bool // tracks files that were changed since the last scan per workspace folder
	learnService      learn.Service
	fileFilters       *xsync.MapOf[string, *filefilter.FileFilter]
	notifier          notification.Notifier

	// global map to store last used bundle hashes for each workspace folder
	// these are needed when we want to retrieve auto-fixes for a previously
	// analyzed folder
	bundleHashes map[string]string
	codeScanner  codeClient.CodeScanner
	// this is the local scanner issue cache. In the future, it should be used as source of truth for the issues
	// the cache in workspace/folder should just delegate to this cache
	issueCache          *imcache.Cache[string, []snyk.Issue]
	cacheRemovalHandler func(path string)
	c                   *config.Config
}

func (sc *Scanner) BundleHashes() map[string]string {
	sc.bundleHashesMutex.RLock()
	defer sc.bundleHashesMutex.RUnlock()
	return sc.bundleHashes
}

func (sc *Scanner) AddBundleHash(key, value string) {
	sc.bundleHashesMutex.Lock()
	defer sc.bundleHashesMutex.Unlock()
	if sc.bundleHashes == nil {
		sc.bundleHashes = make(map[string]string)
	}
	sc.bundleHashes[key] = value
}

func (sc *Scanner) DeltaScanningEnabled() bool {
	return sc.c.IsDeltaFindingsEnabled()
}

func New(bundleUploader *BundleUploader, apiClient snyk_api.SnykApiClient, reporter codeClientObservability.ErrorReporter, learnService learn.Service, notifier notification.Notifier, codeScanner codeClient.CodeScanner) *Scanner {
	sc := &Scanner{
		BundleUploader: bundleUploader,
		SnykApiClient:  apiClient,
		errorReporter:  reporter,
		runningScans:   map[string]*ScanStatus{},
		changedPaths:   map[string]map[string]bool{},
		fileFilters:    xsync.NewMapOf[*filefilter.FileFilter](),
		learnService:   learnService,
		notifier:       notifier,
		bundleHashes:   map[string]string{},
		codeScanner:    codeScanner,
		c:              bundleUploader.c,
	}
	sc.issueCache = imcache.New[string, []snyk.Issue](
		imcache.WithDefaultExpirationOption[string, []snyk.Issue](time.Hour * 12),
	)
	return sc
}

func (sc *Scanner) IsEnabled() bool {
	return sc.c.IsSnykCodeEnabled() ||
		sc.c.IsSnykCodeQualityEnabled() ||
		sc.c.IsSnykCodeSecurityEnabled()
}

func (sc *Scanner) Product() product.Product {
	return product.ProductCode
}

func (sc *Scanner) SupportedCommands() []types.CommandName {
	return []types.CommandName{types.NavigateToRangeCommand}
}

func (sc *Scanner) Scan(ctx context.Context, path string, folderPath string) (issues []snyk.Issue, err error) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "code.Scan").Logger()
	if !c.NonEmptyToken() {
		logger.Info().Msg("not authenticated, not scanning")
		return issues, err
	}
	sastResponse, err := sc.SnykApiClient.SastSettings()

	if err != nil {
		logger.Error().Err(err).Msg("couldn't get sast enablement")
		sc.errorReporter.CaptureError(err, codeClientObservability.ErrorReporterOptions{})
		return issues, errors.New("couldn't get sast enablement")
	}

	if !sc.isSastEnabled(sastResponse) {
		return issues, errors.New("SAST is not enabled")
	}

	if sc.isLocalEngineEnabled(sastResponse) {
		sc.updateCodeApiLocalEngine(sastResponse)
	}

	sc.changedFilesMutex.Lock()
	if sc.changedPaths[folderPath] == nil {
		sc.changedPaths[folderPath] = map[string]bool{}
	}
	sc.changedPaths[folderPath][path] = true
	sc.changedFilesMutex.Unlock()

	// When starting a scan for a folderPath that's already scanned, the new scan will wait for the previous scan
	// to finish before starting.
	// When there's already a scan waiting, the function returns immediately with empty results.
	scanStatus := NewScanStatus()
	isAlreadyWaiting := sc.waitForScanToFinish(scanStatus, folderPath)
	if isAlreadyWaiting {
		return []snyk.Issue{}, nil // Returning an empty slice implies that no issues were found
	}
	defer func() {
		sc.scanStatusMutex.Lock()
		scanStatus.isRunning = false
		close(scanStatus.finished)
		sc.scanStatusMutex.Unlock()
	}()

	// Proceed to scan only if there are any changed paths. This ensures the following race condition coverage:
	// It could be that one of throttled scans updated the changedPaths set, but the initial scan has picked up it's updated and proceeded with a scan in the meantime.
	sc.changedFilesMutex.Lock()
	if len(sc.changedPaths[folderPath]) <= 0 {
		sc.changedFilesMutex.Unlock()
		return []snyk.Issue{}, nil
	}

	filesToBeScanned := sc.getFilesToBeScanned(folderPath)
	sc.changedFilesMutex.Unlock()

	results, err := internalScan(ctx, sc, folderPath, logger, filesToBeScanned)
	if err != nil {
		return nil, err
	}
	results = filterCodeIssues(c, results)
	// Populate HTML template
	sc.enhanceIssuesDetails(results, folderPath)

	sc.removeFromCache(filesToBeScanned)
	sc.addToCache(results)
	return results, err
}

func filterCodeIssues(c *config.Config, issues []snyk.Issue) []snyk.Issue {
	if c.IsSnykCodeSecurityEnabled() && c.IsSnykCodeQualityEnabled() {
		return issues
	}
	var result []snyk.Issue
	for _, issue := range issues {
		additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
		if !ok {
			continue
		}
		shouldAdd := additionalData.IsSecurityType && c.IsSnykCodeSecurityEnabled() || !additionalData.IsSecurityType && c.IsSnykCodeQualityEnabled()
		if shouldAdd {
			result = append(result, issue)
		}
	}
	return result
}

func internalScan(ctx context.Context, sc *Scanner, folderPath string, logger zerolog.Logger, filesToBeScanned map[string]bool) (results []snyk.Issue, err error) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.ScanWorkspace")
	defer sc.BundleUploader.instrumentor.Finish(span)
	ctx, cancel := context.WithCancel(span.Context())
	defer cancel()

	t := progress.NewTracker(true)
	// monitor external tracker & context cancellations
	go func() { t.CancelOrDone(cancel, ctx.Done()) }()

	t.BeginWithMessage("Snyk Code: scanning "+folderPath, "starting scan")
	defer t.EndWithMessage("Snyk Code: scan of " + folderPath + " done")

	fileFilter, _ := sc.fileFilters.Load(folderPath)
	if fileFilter == nil {
		fileFilter = filefilter.NewFileFilter(folderPath, &logger)
		sc.fileFilters.Store(folderPath, fileFilter)
	}
	files := fileFilter.FindNonIgnoredFiles(t)

	if t.IsCanceled() || ctx.Err() != nil {
		progress.Cancel(t.GetToken())
		return results, err
	}

	if sc.useIgnoresFlow() {
		results, err = sc.UploadAndAnalyzeWithIgnores(ctx, folderPath, files, filesToBeScanned, t)
	} else {
		results, err = sc.UploadAndAnalyze(ctx, files, folderPath, filesToBeScanned, t)
	}
	return results, err
}

// Populate HTML template
func (sc *Scanner) enhanceIssuesDetails(issues []snyk.Issue, folderPath string) {
	logger := sc.c.Logger().With().Str("method", "issue_enhancer.enhanceIssuesDetails").Logger()

	for i := range issues {
		issue := &issues[i]
		issueData, ok := issue.AdditionalData.(snyk.CodeIssueData)
		if !ok {
			logger.Error().Msg("Failed to fetch additional data")
			continue
		}

		lesson, err := sc.learnService.GetLesson(issue.Ecosystem, issue.ID, issue.CWEs, issue.CVEs, issue.IssueType)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to get lesson")
			sc.errorReporter.CaptureError(err, codeClientObservability.ErrorReporterOptions{ErrorDiagnosticPath: ""})
		} else if lesson != nil && lesson.Url != "" {
			issue.LessonUrl = lesson.Url
		}
		issue.AdditionalData = issueData
	}
}

// getFilesToBeScanned returns a map of files that need to be scanned and removes them from the changedPaths set.
// This function also analyzes interfile dependencies, taking into account the dataflow between files.
func (sc *Scanner) getFilesToBeScanned(folderPath string) map[string]bool {
	logger := config.CurrentConfig().Logger().With().Str("method", "code.getFilesToBeScanned").Logger()
	changedFiles := make(map[string]bool)
	for changedPath := range sc.changedPaths[folderPath] {
		if uri.IsDirectory(changedPath) {
			logger.Debug().Str("path", changedPath).Msg("skipping directory")
			continue
		}
		changedFiles[changedPath] = true
		delete(sc.changedPaths[folderPath], changedPath)
		logger.Debug().Str("path", changedPath).Msg("added to changed files")

		// determine interfile dependencies
		cache := sc.issueCache.GetAll()
		for filePath, fileIssues := range cache {
			referencedFiles := getReferencedFiles(fileIssues)
			for _, referencedFile := range referencedFiles {
				if referencedFile == changedPath {
					changedFiles[filePath] = true
					logger.Debug().Str("path", filePath).Str("referencedFile", referencedFile).Msg("added to changed files")
				}
			}
		}
	}
	return changedFiles
}

func getReferencedFiles(issues []snyk.Issue) []string {
	var referencedFiles []string
	for _, issue := range issues {
		if issue.AdditionalData == nil {
			continue
		}
		codeIssueData, ok := issue.AdditionalData.(snyk.CodeIssueData)
		if !ok {
			continue
		}
		for _, dataFlow := range codeIssueData.DataFlow {
			referencedFiles = append(referencedFiles, dataFlow.FilePath)
		}
	}
	return referencedFiles
}

func (sc *Scanner) waitForScanToFinish(scanStatus *ScanStatus, folderPath string) bool {
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

func (sc *Scanner) UploadAndAnalyze(ctx context.Context, files <-chan string, path string, changedFiles map[string]bool, t *progress.Tracker) (issues []snyk.Issue, err error) {
	if ctx.Err() != nil {
		progress.Cancel(t.GetToken())
		sc.c.Logger().Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
		return issues, nil
	}

	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.uploadAndAnalyze")
	defer sc.BundleUploader.instrumentor.Finish(span)

	requestId := span.GetTraceId() // use span trace id as code-request-id
	sc.c.Logger().Info().Str("requestId", requestId).Msg("Starting Code analysis.")

	bundle, err := sc.createBundle(span.Context(), requestId, path, files, changedFiles, t)

	errorReporterOptions := codeClientObservability.ErrorReporterOptions{ErrorDiagnosticPath: path}

	if err != nil {
		if isNoFilesError(err) {
			return issues, nil
		}
		if ctx.Err() == nil { // Only report errors that are not intentional cancellations
			msg := "error creating bundle..."
			sc.errorReporter.CaptureError(errors.Wrap(err, msg), errorReporterOptions)
			return issues, err
		} else {
			progress.Cancel(t.GetToken())
			sc.c.Logger().Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return issues, nil
		}
	}

	uploadedBundle, err := sc.BundleUploader.Upload(span.Context(), bundle, bundle.Files, t)
	if err != nil {
		if ctx.Err() == nil { // Only handle errors that are not intentional cancellations
			msg := "error uploading files..."
			sc.errorReporter.CaptureError(errors.Wrap(err, msg), errorReporterOptions)
			return issues, err
		} else {
			sc.c.Logger().Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			progress.Cancel(t.GetToken())
			return issues, nil
		}
	}

	if uploadedBundle.BundleHash == "" {
		sc.c.Logger().Debug().Msg("empty bundle, no Snyk Code analysis")
		return issues, nil
	}

	sc.bundleHashesMutex.Lock()
	sc.bundleHashes[path] = uploadedBundle.BundleHash
	sc.bundleHashesMutex.Unlock()

	issues, err = uploadedBundle.FetchDiagnosticsData(span.Context(), t)
	if ctx.Err() != nil || t.IsCanceled() {
		progress.Cancel(t.GetToken())
		sc.c.Logger().Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
		return []snyk.Issue{}, nil
	}
	return issues, err
}

func (sc *Scanner) UploadAndAnalyzeWithIgnores(ctx context.Context, path string, files <-chan string, changedFiles map[string]bool, t *progress.Tracker) (issues []snyk.Issue, err error) {
	if ctx.Err() != nil {
		progress.Cancel(t.GetToken())
		sc.c.Logger().Info().Msg("Canceling Code scanner received cancellation signal")
		return issues, nil
	}

	logger := sc.c.Logger().With().Str("method", "code.UploadAndAnalyzeWithIgnores").Logger()
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.uploadAndAnalyze")
	defer sc.BundleUploader.instrumentor.Finish(span)

	requestId := span.GetTraceId() // use span trace id as code-request-id
	logger.Info().Str("requestId", requestId).Msg("Starting Code analysis.")

	target, err := scan.NewRepositoryTarget(path)

	if err != nil {
		logger.Warn().Msg("could not determine repository URL (target)")
	}

	sarif, bundleHash, err := sc.codeScanner.UploadAndAnalyze(ctx, requestId, target, files, changedFiles)
	if err != nil || ctx.Err() != nil {
		return []snyk.Issue{}, err
	}
	sc.bundleHashesMutex.Lock()
	sc.bundleHashes[path] = bundleHash
	sc.bundleHashesMutex.Unlock()

	converter := SarifConverter{sarif: *sarif, c: sc.c}
	issues, err = converter.toIssues(path)
	if err != nil {
		return []snyk.Issue{}, err
	}
	issueEnhancer := newIssueEnhancer(
		sc.BundleUploader.SnykCode,
		sc.BundleUploader.instrumentor,
		sc.errorReporter,
		sc.notifier,
		sc.learnService,
		requestId,
		path,
		sc.c,
	)
	issueEnhancer.addIssueActions(ctx, issues, bundleHash)

	return issues, nil
}

type noFilesError struct{}

func (e noFilesError) Error() string { return "no files to scan" }

func isNoFilesError(err error) bool {
	var myErr noFilesError
	ok := errors.As(err, &myErr)
	return ok
}

func (sc *Scanner) createBundle(ctx context.Context, requestId string, rootPath string, filePaths <-chan string, changedFiles map[string]bool, t *progress.Tracker) (Bundle, error) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.createBundle")
	defer sc.BundleUploader.instrumentor.Finish(span)

	t.ReportWithMessage(15, "creating file bundle")

	var limitToFiles []string
	fileHashes := make(map[string]string)
	bundleFiles := make(map[string]BundleFile)
	noFiles := true
	for absoluteFilePath := range filePaths {
		if ctx.Err() != nil || t.IsCanceled() {
			progress.Cancel(t.GetToken())
			sc.c.Logger().Info().Msg("Canceling Code scan - Code scanner received cancellation signal")
			return Bundle{}, ctx.Err()
		}
		noFiles = false
		supported, err := sc.BundleUploader.isSupported(span.Context(), absoluteFilePath)
		if err != nil {
			return Bundle{}, err
		}
		if !supported {
			continue
		}

		fileContent, err := os.ReadFile(absoluteFilePath)
		if err != nil {
			sc.c.Logger().Error().Err(err).Str("filePath", absoluteFilePath).Msg("could not load content of file")
			continue
		}

		if !(len(fileContent) > 0 && len(fileContent) <= maxFileSize) {
			continue
		}

		relativePath, err := ToRelativeUnixPath(rootPath, absoluteFilePath)
		if err != nil {
			sc.errorReporter.CaptureError(err, codeClientObservability.ErrorReporterOptions{ErrorDiagnosticPath: rootPath})
		}
		relativePath = EncodePath(relativePath)

		bundleFile := sc.getFileFrom(absoluteFilePath, fileContent)
		bundleFiles[relativePath] = bundleFile
		fileHashes[relativePath] = bundleFile.Hash

		if changedFiles[absoluteFilePath] {
			limitToFiles = append(limitToFiles, relativePath)
		}
	}

	if noFiles {
		return Bundle{}, noFilesError{}
	}

	b := Bundle{
		SnykCode:      sc.BundleUploader.SnykCode,
		Files:         bundleFiles,
		instrumentor:  sc.BundleUploader.instrumentor,
		requestId:     requestId,
		rootPath:      rootPath,
		errorReporter: sc.errorReporter,
		limitToFiles:  limitToFiles,
		issueEnhancer: newIssueEnhancer(
			sc.BundleUploader.SnykCode,
			sc.BundleUploader.instrumentor,
			sc.errorReporter,
			sc.notifier,
			sc.learnService,
			requestId,
			rootPath,
			sc.c,
		),
		logger: sc.c.Logger(),
	}
	var err error
	if len(fileHashes) > 0 {
		b.BundleHash, b.missingFiles, err = sc.BundleUploader.SnykCode.CreateBundle(span.Context(), fileHashes)
	}
	return b, err
}

type UploadStatus struct {
	UploadedFiles int
	TotalFiles    int
}

func (sc *Scanner) useIgnoresFlow() bool {
	logger := config.CurrentConfig().Logger().With().Str("method", "code.useIgnoresFlow").Logger()
	response, err := sc.SnykApiClient.FeatureFlagStatus(snyk_api.FeatureFlagSnykCodeConsistentIgnores)
	if err != nil {
		logger.Debug().Msg("Failed to check if the ignores experience is enabled")
		return false
	}
	if !response.Ok && response.UserMessage != "" {
		logger.Info().Msg(response.UserMessage)
	}
	return response.Ok
}
