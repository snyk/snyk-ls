package secrets

import (
	"context"
	"sync"
	"time"

	"github.com/erni27/imcache"
	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"

	codeClient "github.com/snyk/code-client-go"
	codeClientObservability "github.com/snyk/code-client-go/observability"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
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
	SnykApiClient     snyk_api.SnykApiClient
	errorReporter     codeClientObservability.ErrorReporter
	bundleHashesMutex sync.RWMutex
	changedFilesMutex sync.RWMutex
	scanStatusMutex   sync.RWMutex
	runningScans      map[types.FilePath]*ScanStatus
	changedPaths      map[types.FilePath]map[types.FilePath]bool // tracks files that were changed since the last scan per workspace folder
	learnService      learn.Service
	fileFilters       *xsync.MapOf[string, *utils.FileFilter]
	notifier          notification.Notifier

	// global map to store last used bundle hashes for each workspace folder
	// these are needed when we want to retrieve auto-fixes for a previously
	// analyzed folder
	bundleHashes map[types.FilePath]string
	codeScanner  func(sc *Scanner, folderConfig *types.FolderConfig) (codeClient.CodeScanner, error)
	// this is the local scanner issue cache. In the future, it should be used as source of truth for the issues
	// the cache in workspace/folder should just delegate to this cache
	issueCache          *imcache.Cache[types.FilePath, []types.Issue]
	cacheRemovalHandler func(path types.FilePath)
	C                   *config.Config
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

func New(config *config.Config, apiClient snyk_api.SnykApiClient, reporter codeClientObservability.ErrorReporter, learnService learn.Service, notifier notification.Notifier, codeScanner func(sc *Scanner, folderConfig *types.FolderConfig) (codeClient.CodeScanner, error)) *Scanner {
	sc := &Scanner{
		SnykApiClient: apiClient,
		errorReporter: reporter,
		runningScans:  map[types.FilePath]*ScanStatus{},
		changedPaths:  map[types.FilePath]map[types.FilePath]bool{},
		fileFilters:   xsync.NewMapOf[*utils.FileFilter](),
		learnService:  learnService,
		notifier:      notifier,
		bundleHashes:  map[types.FilePath]string{},
		codeScanner:   codeScanner,
		C:             config,
	}
	sc.issueCache = imcache.New[types.FilePath, []types.Issue](
		imcache.WithDefaultExpirationOption[types.FilePath, []types.Issue](time.Hour * 12),
	)
	return sc
}

func (sc *Scanner) IsEnabled() bool {
	return sc.C.IsSnykSecretsEnabled()
}

func (sc *Scanner) Product() product.Product {
	return product.ProductSecrets
}

func (sc *Scanner) SupportedCommands() []types.CommandName {
	return []types.CommandName{types.NavigateToRangeCommand}
}

func (sc *Scanner) Scan(ctx context.Context, path types.FilePath, folderPath types.FilePath, _ *types.FolderConfig) (issues []types.Issue, err error) {
	return nil, nil
}

func internalScan(folderPath types.FilePath, logger zerolog.Logger) (results []types.Issue, err error) {
	return nil, nil
}

// Populate HTML template
func (sc *Scanner) enhanceIssuesDetails(issues []types.Issue) {
	logger := sc.C.Logger().With().Str("method", "issue_enhancer.enhanceIssuesDetails").Logger()

	for i := range issues {
		issue := issues[i]
		issueData, ok := issue.GetAdditionalData().(snyk.SecretsIssueData)
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

type noFilesError struct{}

func (e noFilesError) Error() string { return "no files to scan" }

func isNoFilesError(err error) bool {
	var myErr noFilesError
	ok := errors.As(err, &myErr)
	return ok
}
