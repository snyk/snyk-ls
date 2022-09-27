package code

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/float"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/util"
)

type ScanMetrics struct {
	lastScanStartTime         time.Time
	lastScanDurationInSeconds float64
	lastScanFileCount         int
}

type Scanner struct {
	BundleUploader *BundleUploader
	SnykApiClient  snyk_api.SnykApiClient
	errorReporter  error_reporting.ErrorReporter
	analytics      ux2.Analytics
	ignorePatterns []string
	mutex          sync.Mutex
}

func New(bundleUploader *BundleUploader, apiClient snyk_api.SnykApiClient, reporter error_reporting.ErrorReporter, analytics ux2.Analytics) *Scanner {
	sc := &Scanner{
		BundleUploader: bundleUploader,
		SnykApiClient:  apiClient,
		errorReporter:  reporter,
		analytics:      analytics,
	}
	return sc
}

func (sc *Scanner) IsEnabled() bool {
	return config.CurrentConfig().IsSnykCodeEnabled()
}

func (sc *Scanner) Product() snyk.Product {
	return snyk.ProductCode
}

func (sc *Scanner) SupportedCommands() []snyk.CommandName {
	return []snyk.CommandName{snyk.NavigateToRangeCommand}
}

func (sc *Scanner) Scan(ctx context.Context, _ string, folderPath string, concurrentScansSemaphore chan int) []snyk.Issue {
	concurrentScansSemaphore <- 1
	defer func() {
		<-concurrentScansSemaphore
	}()
	startTime := time.Now()
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.ScanWorkspace")
	defer sc.BundleUploader.instrumentor.Finish(span)

	files, err := sc.files(folderPath)
	if err != nil {
		log.Warn().
			Err(err).
			Str("method", "domain.ide.workspace.Folder.ScanFolder").
			Str("workspaceFolderPath", folderPath).
			Msg("error getting workspace files")
	}

	metrics := sc.newMetrics(len(files), startTime)
	return sc.UploadAndAnalyze(span.Context(), files, folderPath, metrics)
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
	if sc.ignorePatterns == nil {
		fileCount, err = sc.loadIgnorePatternsAndCountFiles(folderPath)
		if err != nil {
			return filePaths, err
		}
	}

	gitIgnore := ignore.CompileIgnoreLines(sc.ignorePatterns...)
	sc.mutex.Unlock()
	filesWalked := 0
	log.Debug().Str("method", "folder.Files").Msgf("Filecount: %d", fileCount)
	err = filepath.WalkDir(workspace, func(path string, dirEntry os.DirEntry, err error) error {
		filesWalked++
		percentage := math.Round(float64(filesWalked) / float64(fileCount) * 100)
		t.ReportWithMessage(
			int(percentage),
			fmt.Sprintf("Loading file contents for scan... (%d of %d)", filesWalked, fileCount))
		if err != nil {
			log.Debug().
				Str("method", "domain.ide.workspace.Folder.Files").
				Str("path", path).
				Err(err).
				Msg("error traversing files")
			return nil
		}
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
	})
	t.End("All relevant files collected")
	if err != nil {
		return filePaths, err
	}
	return filePaths, nil
}

func (sc *Scanner) loadIgnorePatternsAndCountFiles(folderPath string) (fileCount int, err error) {
	var ignores = ""
	log.Debug().
		Str("method", "loadIgnorePatternsAndCountFiles").
		Str("workspace", folderPath).
		Msg("searching for ignore files")
	err = filepath.WalkDir(folderPath, func(path string, dirEntry os.DirEntry, err error) error {
		fileCount++
		if err != nil {
			log.Debug().
				Str("method", "loadIgnorePatternsAndCountFiles - walker").
				Str("path", path).
				Err(err).
				Msg("error traversing files")
			return nil
		}
		if dirEntry == nil || dirEntry.IsDir() {
			return nil
		}

		if !(strings.HasSuffix(path, ".gitignore") || strings.HasSuffix(path, ".dcignore")) {
			return nil
		}
		log.Debug().Str("method", "loadIgnorePatternsAndCountFiles").Str("file", path).Msg("found ignore file")
		content, err := os.ReadFile(path)
		if err != nil {
			log.Err(err).Msg("Can't read" + path)
		}
		ignores += string(content)
		return err
	})

	if err != nil {
		return fileCount, err
	}

	patterns := strings.Split(ignores, "\n")
	sc.ignorePatterns = patterns
	log.Debug().Interface("ignorePatterns", patterns).Msg("Loaded and set ignore patterns")
	return fileCount, nil
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

func (sc *Scanner) UploadAndAnalyze(ctx context.Context, files []string, path string, scanMetrics *ScanMetrics) (issues []snyk.Issue) {
	if ctx.Err() != nil {
		log.Info().Msg("Cancelling Code scan - Code scanner received cancellation signal")
		return issues
	}

	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.uploadAndAnalyze")
	defer sc.BundleUploader.instrumentor.Finish(span)
	if len(files) == 0 {
		return issues
	}

	if !sc.isSastEnabled() {
		return issues
	}

	requestId := span.GetTraceId() // use span trace id as code-request-id

	bundle, bundleFiles, err := sc.createBundle(span.Context(), requestId, path, files)

	if err != nil {
		if ctx.Err() == nil { // Only report errors that are not intentional cancellations
			msg := "error creating bundle..."
			sc.handleCreationAndUploadError(err, msg, scanMetrics)
		} else {
			log.Info().Msg("Cancelling Code scan - Code scanner received cancellation signal")
		}
		return issues
	}

	uploadedBundle, err := sc.BundleUploader.Upload(span.Context(), bundle, bundleFiles)
	// TODO LSP error handling should be pushed UP to the LSP layer
	if err != nil {
		if ctx.Err() != nil { // Only handle errors that are not intentional cancellations
			msg := "error uploading files..."
			sc.handleCreationAndUploadError(err, msg, scanMetrics)
		} else {
			log.Info().Msg("Cancelling Code scan - Code scanner received cancellation signal")
		}
		return issues
	}

	if uploadedBundle.BundleHash == "" {
		log.Info().Msg("empty bundle, no Snyk Code analysis")
		return issues
	}

	issues = uploadedBundle.FetchDiagnosticsData(span.Context())
	if ctx.Err() != nil {
		log.Info().Msg("Cancelling Code scan - Code scanner received cancellation signal")
		return []snyk.Issue{}
	}
	sc.trackResult(true, scanMetrics)
	return issues
}

func (sc *Scanner) handleCreationAndUploadError(err error, msg string, scanMetrics *ScanMetrics) {
	sc.errorReporter.CaptureError(errors.Wrap(err, msg))
	sc.trackResult(err == nil, scanMetrics)
}

func (sc *Scanner) createBundle(ctx context.Context, requestId string, rootPath string, filePaths []string) (b Bundle, bundleFiles map[string]BundleFile, err error) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.createBundle")
	defer sc.BundleUploader.instrumentor.Finish(span)
	b = Bundle{
		SnykCode:      sc.BundleUploader.SnykCode,
		instrumentor:  sc.BundleUploader.instrumentor,
		requestId:     requestId,
		rootPath:      rootPath,
		errorReporter: sc.errorReporter,
	}

	fileHashes := make(map[string]string)
	bundleFiles = make(map[string]BundleFile)
	for _, filePath := range filePaths {
		if ctx.Err() != nil {
			return b, nil, err // The cancellation error should be handled by the calling function
		}
		if !sc.BundleUploader.isSupported(span.Context(), filePath) {
			continue
		}
		fileContent, err := loadContent(filePath)
		if err != nil {
			log.Error().Err(err).Str("filePath", filePath).Msg("could not load content of file")
			continue
		}

		if !(len(fileContent) > 0 && len(fileContent) <= maxFileSize) {
			continue
		}
		file := getFileFrom(filePath, fileContent)
		bundleFiles[filePath] = file
		fileHashes[filePath] = file.Hash
	}
	if len(fileHashes) > 0 {
		b.BundleHash, b.missingFiles, err = sc.BundleUploader.SnykCode.CreateBundle(span.Context(), fileHashes)
	}
	return b, bundleFiles, err
}

func (sc *Scanner) isSastEnabled() bool {
	sastEnabled, localCodeEngineEnabled, _, err := sc.SnykApiClient.SastEnabled()
	if err != nil {
		log.Error().Err(err).Str("method", "isSastEnabled").Msg("couldn't get sast enablement")
		sc.errorReporter.CaptureError(err)
		return false
	}
	if !sastEnabled {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Snyk Code is disabled by your organisation's configuration."})
		return false
	} else {
		if localCodeEngineEnabled {
			notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Snyk Code is configured to use a Local Code Engine instance. This setup is not yet supported."})
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
	sc.analytics.AnalysisIsReady(ux2.AnalysisIsReadyProperties{
		AnalysisType:      ux2.CodeSecurity,
		Result:            result,
		FileCount:         scanMetrics.lastScanFileCount,
		DurationInSeconds: scanMetrics.lastScanDurationInSeconds,
	})
}
