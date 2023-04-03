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
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/float"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
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
	mutex             sync.Mutex
	scanStatusMutex   sync.Mutex
	runningScans      map[string]*ScanStatus
	scanNotifier      snyk.ScanNotifier
	changedPaths      map[string]map[string]bool // tracks files that were changed since the last scan per workspace folder
}

func New(bundleUploader *BundleUploader,
	apiClient snyk_api.SnykApiClient,
	reporter error_reporting.ErrorReporter,
	analytics ux2.Analytics,
) *Scanner {
	sc := &Scanner{
		BundleUploader: bundleUploader,
		SnykApiClient:  apiClient,
		errorReporter:  reporter,
		analytics:      analytics,
		runningScans:   map[string]*ScanStatus{},
		changedPaths:   map[string]map[string]bool{},
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
	folderFiles, err := sc.files(folderPath)
	if err != nil {
		log.Warn().
			Err(err).
			Str("method", "domain.ide.workspace.Folder.ScanFolder").
			Str("workspaceFolderPath", folderPath).
			Msg("error getting workspace files")
	}

	metrics := sc.newMetrics(len(folderFiles), startTime)
	results, err := sc.UploadAndAnalyze(span.Context(), folderFiles, folderPath, metrics, changedFiles)

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

func (sc *Scanner) files(folderPath string) (filePaths []string, err error) {
	t := progress.NewTracker(false)
	workspace, err := filepath.Abs(folderPath)
	t.Begin(fmt.Sprintf("Snyk Code: Enumerating files in %s", folderPath), "Evaluating ignores and counting files...")

	if err != nil {
		return filePaths, err
	}
	sc.mutex.Lock()
	var fileCount int
	var ignorePatterns []string
	ignorePatterns, fileCount, err = sc.loadIgnorePatternsAndCountFiles(folderPath)
	if err != nil {
		return filePaths, err
	}

	gitIgnore := ignore.CompileIgnoreLines(ignorePatterns...)
	sc.mutex.Unlock()
	filesWalked := 0
	log.Debug().Str("method", "folder.Files").Msgf("File count: %d", fileCount)
	err = filepath.WalkDir(
		workspace, func(path string, dirEntry os.DirEntry, err error) error {
			if err != nil {
				log.Debug().
					Str("method", "domain.ide.workspace.Folder.Files").
					Str("path", path).
					Err(err).
					Msg("error traversing files")
				return nil
			}
			filesWalked++
			percentage := math.Round(float64(filesWalked) / float64(fileCount) * 100)
			t.ReportWithMessage(
				int(percentage),
				fmt.Sprintf("Loading file contents for scan... (%d of %d)", filesWalked, fileCount),
			)
			if dirEntry == nil || dirEntry.IsDir() {
				if util.Ignored(gitIgnore, path) {
					return filepath.SkipDir
				}
				return nil
			}

			if util.Ignored(gitIgnore, path) {
				return nil
			}

			filePaths = append(filePaths, path)
			return err
		},
	)
	t.End("All relevant files collected")
	if err != nil {
		return filePaths, err
	}
	return filePaths, nil
}

func (sc *Scanner) newMetrics(fileCount int, scanStartTime time.Time) *ScanMetrics {
	if scanStartTime.IsZero() {
		scanStartTime = time.Now()
	}

	return &ScanMetrics{
		lastScanStartTime: scanStartTime,
		lastScanFileCount: fileCount,
	}
}

func (sc *Scanner) UploadAndAnalyze(ctx context.Context,
	files []string,
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
	if len(files) == 0 {
		return issues, nil
	}

	requestId := span.GetTraceId() // use span trace id as code-request-id

	bundle, err := sc.createBundle(span.Context(), requestId, path, files, changedFiles)
	if err != nil {
		if ctx.Err() == nil { // Only report errors that are not intentional cancellations
			msg := "error creating bundle..."
			sc.handleCreationAndUploadError(path, err, msg, scanMetrics)
			return issues, err
		} else {
			log.Info().Msg("Cancelling Code scan - Code scanner received cancellation signal")
			return issues, nil
		}
	}

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

func (sc *Scanner) createBundle(ctx context.Context,
	requestId string,
	rootPath string,
	filePaths []string,
	changedFiles map[string]bool,
) (b Bundle, err error) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.createBundle")
	defer sc.BundleUploader.instrumentor.Finish(span)

	var limitToFiles []string
	fileHashes := make(map[string]string)
	bundleFiles := make(map[string]BundleFile)
	for _, absoluteFilePath := range filePaths {
		if ctx.Err() != nil {
			return b, err // The cancellation error should be handled by the calling function
		}
		if !sc.BundleUploader.isSupported(span.Context(), absoluteFilePath) {
			continue
		}
		fileContent, err := loadContent(absoluteFilePath)
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

	b = Bundle{
		SnykCode:      sc.BundleUploader.SnykCode,
		Files:         bundleFiles,
		instrumentor:  sc.BundleUploader.instrumentor,
		requestId:     requestId,
		rootPath:      rootPath,
		errorReporter: sc.errorReporter,
		scanNotifier:  sc.scanNotifier,
		limitToFiles:  limitToFiles,
	}
	if len(fileHashes) > 0 {
		b.BundleHash, b.missingFiles, err = sc.BundleUploader.SnykCode.CreateBundle(span.Context(), fileHashes)
	}
	return b, err
}

const codeDisabledInOrganisationMessageText = "It looks like your organization has disabled Snyk Code. " +
	"You can easily enable it by clicking on 'Enable Snyk Code'. " +
	"This will open your organization settings in your browser."

const enableSnykCodeMessageActionItemTitle snyk.MessageAction = "Enable Snyk Code"
const closeMessageActionItemTitle snyk.MessageAction = "Close"

func (sc *Scanner) isSastEnabled() bool {
	sastEnabled, localCodeEngineEnabled, _, err := sc.SnykApiClient.SastEnabled()
	if err != nil {
		log.Error().Err(err).Str("method", "isSastEnabled").Msg("couldn't get sast enablement")
		sc.errorReporter.CaptureError(err)
		return false
	}
	if !sastEnabled {
		// this is processed in the listener registered to translate into the right client protocol
		actionCommandMap := data_structure.NewOrderedMap[snyk.MessageAction, snyk.Command]()
		commandData := snyk.CommandData{
			Title:     snyk.OpenBrowserCommand,
			CommandId: snyk.OpenBrowserCommand,
			Arguments: []any{getCodeEnablementUrl()},
		}
		cmd, err := command.CreateFromCommandData(commandData, nil, nil)
		if err != nil {
			log.Error().Err(err).Str("method", "isSastEnabled").Msg("couldn't create open browser command")
		} else {
			actionCommandMap.Add(enableSnykCodeMessageActionItemTitle, cmd)
		}
		actionCommandMap.Add(closeMessageActionItemTitle, nil)

		notification.Send(snyk.ShowMessageRequest{
			Message: codeDisabledInOrganisationMessageText,
			Type:    snyk.Warning,
			Actions: actionCommandMap,
		})
		return false
	} else {
		if localCodeEngineEnabled {
			notification.SendShowMessage(
				sglsp.Warning,
				"Snyk Code is configured to use a Local Code Engine instance. This setup is not yet supported.",
			)
			return false
		}
		return true
	}
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
