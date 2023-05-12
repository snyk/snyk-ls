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

package code

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/filefilter"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/float"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
)

type ScanMetrics struct {
	lastScanStartTime         time.Time
	lastScanDurationInSeconds float64
	lastScanFileCount         int
}

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
	errorReporter     error_reporting.ErrorReporter
	analytics         ux2.Analytics
	changedFilesMutex sync.Mutex
	scanStatusMutex   sync.Mutex
	runningScans      map[string]*ScanStatus
	changedPaths      map[string]map[string]bool // tracks files that were changed since the last scan per workspace folder
	learnService      learn.Service
	fileFilters       *xsync.MapOf[string, *filefilter.FileFilter]
	notifier          notification.Notifier
}

func New(bundleUploader *BundleUploader,
	apiClient snyk_api.SnykApiClient,
	reporter error_reporting.ErrorReporter,
	analytics ux2.Analytics,
	learnService learn.Service,
	notifier notification.Notifier,
) *Scanner {
	sc := &Scanner{
		BundleUploader: bundleUploader,
		SnykApiClient:  apiClient,
		errorReporter:  reporter,
		analytics:      analytics,
		runningScans:   map[string]*ScanStatus{},
		changedPaths:   map[string]map[string]bool{},
		fileFilters:    xsync.NewMapOf[*filefilter.FileFilter](),
		learnService:   learnService,
		notifier:       notifier,
	}
	return sc
}

func (sc *Scanner) IsEnabled() bool {
	currentConfig := config.CurrentConfig
	return currentConfig().IsSnykCodeEnabled() ||
		currentConfig().IsSnykCodeQualityEnabled() ||
		currentConfig().IsSnykCodeSecurityEnabled()
}

func (sc *Scanner) Product() product.Product {
	return product.ProductCode
}

func (sc *Scanner) SupportedCommands() []snyk.CommandName {
	return []snyk.CommandName{snyk.NavigateToRangeCommand}
}

func (sc *Scanner) Scan(ctx context.Context, path string, folderPath string) (issues []snyk.Issue, err error) {
	if !sc.isSastEnabled() {
		return issues, errors.New("SAST is not enabled")
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
		return []snyk.Issue{}, nil // Returning an empty slice implies that no vulnerabilities were found
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

	changedFiles := make(map[string]bool)
	for changedPath := range sc.changedPaths[folderPath] {
		if !uri.IsDirectory(changedPath) {
			changedFiles[changedPath] = true
		}
		delete(sc.changedPaths[folderPath], changedPath)
	}
	sc.changedFilesMutex.Unlock()

	startTime := time.Now()
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.ScanWorkspace")
	defer sc.BundleUploader.instrumentor.Finish(span)

	// Start the scan
	t := progress.NewTracker(false)
	t.Begin("Snyk Code: Collecting files in \""+folderPath+"\"", "Evaluating ignores and counting files...")
	fileFilter, _ := sc.fileFilters.Load(folderPath)
	if fileFilter == nil {
		fileFilter = filefilter.NewFileFilter(folderPath, config.CurrentConfig().Logger())
		sc.fileFilters.Store(folderPath, fileFilter)
	}
	files := fileFilter.FindNonIgnoredFiles()
	t.EndWithMessage("Collected files")
	metrics := sc.newMetrics(startTime)
	results, err := sc.UploadAndAnalyze(span.Context(), files, folderPath, metrics, changedFiles)

	return results, err
}

func (sc *Scanner) waitForScanToFinish(scanStatus *ScanStatus, folderPath string) (waiting bool) {
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

func (sc *Scanner) newMetrics(scanStartTime time.Time) *ScanMetrics {
	if scanStartTime.IsZero() {
		scanStartTime = time.Now()
	}

	return &ScanMetrics{
		lastScanStartTime: scanStartTime,
	}
}

func (sc *Scanner) UploadAndAnalyze(ctx context.Context,
	files <-chan string,
	path string,
	scanMetrics *ScanMetrics,
	changedFiles map[string]bool,
) (issues []snyk.Issue, err error) {
	if ctx.Err() != nil {
		log.Info().Msg("Cancelling Code scan - Code scanner received cancellation signal")
		return issues, nil
	}

	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.uploadAndAnalyze")
	defer sc.BundleUploader.instrumentor.Finish(span)

	requestId := span.GetTraceId() // use span trace id as code-request-id
	log.Info().Str("requestId", requestId).Msg("Starting Code analysis.")

	bundle, err := sc.createBundle(span.Context(), requestId, path, files, changedFiles)
	if err != nil {
		if isNoFilesError(err) {
			return issues, nil
		}
		if ctx.Err() == nil { // Only report errors that are not intentional cancellations
			msg := "error creating bundle..."
			sc.handleCreationAndUploadError(path, err, msg, scanMetrics)
			return issues, err
		} else {
			log.Info().Msg("Cancelling Code scan - Code scanner received cancellation signal")
			return issues, nil
		}
	}
	scanMetrics.lastScanFileCount = len(bundle.Files)

	uploadedBundle, err := sc.BundleUploader.Upload(span.Context(), bundle, bundle.Files)
	// TODO LSP error handling should be pushed UP to the LSP layer
	if err != nil {
		if ctx.Err() != nil { // Only handle errors that are not intentional cancellations
			msg := "error uploading files..."
			sc.handleCreationAndUploadError(path, err, msg, scanMetrics)
			return issues, err
		} else {
			log.Info().Msg("Cancelling Code scan - Code scanner received cancellation signal")
			return issues, nil
		}
	}

	if uploadedBundle.BundleHash == "" {
		log.Info().Msg("empty bundle, no Snyk Code analysis")
		return issues, nil
	}

	issues, err = uploadedBundle.FetchDiagnosticsData(span.Context())
	if ctx.Err() != nil {
		log.Info().Msg("Cancelling Code scan - Code scanner received cancellation signal")
		return []snyk.Issue{}, nil
	}
	sc.trackResult(err == nil, scanMetrics)
	return issues, err
}

func (sc *Scanner) handleCreationAndUploadError(path string, err error, msg string, scanMetrics *ScanMetrics) {
	sc.errorReporter.CaptureErrorAndReportAsIssue(path, errors.Wrap(err, msg))
	sc.trackResult(err == nil, scanMetrics)
}

type noFilesError struct{}

func (e noFilesError) Error() string { return "no files to scan" }
func isNoFilesError(err error) bool {
	_, ok := err.(noFilesError)
	return ok
}

func (sc *Scanner) createBundle(ctx context.Context,
	requestId string,
	rootPath string,
	filePaths <-chan string,
	changedFiles map[string]bool,
) (b Bundle, err error) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.createBundle")
	defer sc.BundleUploader.instrumentor.Finish(span)

	var limitToFiles []string
	fileHashes := make(map[string]string)
	bundleFiles := make(map[string]BundleFile)
	noFiles := true
	for absoluteFilePath := range filePaths {
		noFiles = false
		if ctx.Err() != nil {
			return b, err // The cancellation error should be handled by the calling function
		}
		supported, err := sc.BundleUploader.isSupported(span.Context(), absoluteFilePath)
		if err != nil {
			return b, err
		}
		if !supported {
			continue
		}
		fileContent, err := os.ReadFile(absoluteFilePath)
		if err != nil {
			log.Error().Err(err).Str("filePath", absoluteFilePath).Msg("could not load content of file")
			continue
		}

		if !(len(fileContent) > 0 && len(fileContent) <= maxFileSize) {
			continue
		}

		relativePath, err := ToRelativeUnixPath(rootPath, absoluteFilePath)
		if err != nil {
			sc.errorReporter.CaptureErrorAndReportAsIssue(rootPath, err)
		}
		relativePath = EncodePath(relativePath)

		bundleFile := getFileFrom(absoluteFilePath, fileContent)
		bundleFiles[relativePath] = bundleFile
		fileHashes[relativePath] = bundleFile.Hash

		if changedFiles[absoluteFilePath] {
			limitToFiles = append(limitToFiles, relativePath)
		}
	}

	if noFiles {
		return b, noFilesError{}
	}
	b = Bundle{
		SnykCode:      sc.BundleUploader.SnykCode,
		Files:         bundleFiles,
		instrumentor:  sc.BundleUploader.instrumentor,
		requestId:     requestId,
		rootPath:      rootPath,
		errorReporter: sc.errorReporter,
		limitToFiles:  limitToFiles,
		learnService:  sc.learnService,
		notifier:      sc.notifier,
	}
	if len(fileHashes) > 0 {
		b.BundleHash, b.missingFiles, err = sc.BundleUploader.SnykCode.CreateBundle(span.Context(), fileHashes)
	}
	return b, err
}

type UploadStatus struct {
	UploadedFiles int
	TotalFiles    int
}

func (sc *Scanner) trackResult(success bool, scanMetrics *ScanMetrics) {
	var result ux2.Result
	if success {
		result = ux2.Success
	} else {
		result = ux2.Error
	}

	duration := time.Since(scanMetrics.lastScanStartTime)
	scanMetrics.lastScanDurationInSeconds = float.ToFixed(duration.Seconds(), 2)
	sc.analytics.AnalysisIsReady(
		ux2.AnalysisIsReadyProperties{
			AnalysisType:      ux2.CodeSecurity,
			Result:            result,
			FileCount:         scanMetrics.lastScanFileCount,
			DurationInSeconds: scanMetrics.lastScanDurationInSeconds,
		},
	)
}
