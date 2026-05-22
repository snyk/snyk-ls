/*
 * © 2026 Snyk Limited
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

// Package secrets provides Snyk Secret scanning functionality.
package secrets

import (
	"context"
	"sync"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/domain/snyk"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/issuecache"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/scannercommon"
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

var _ snyk.CacheProvider = (*Scanner)(nil)

func NewScanStatus() *ScanStatus {
	return &ScanStatus{
		finished:  make(chan bool),
		isRunning: false,
		isPending: false,
	}
}

type Scanner struct {
	*issuecache.IssueCache
	SnykApiClient      snyk_api.SnykApiClient
	learnService       learn.Service
	scanStatusMutex    sync.RWMutex
	runningScans       map[types.FilePath]*ScanStatus
	changedPaths       map[types.FilePath]map[types.FilePath]bool // tracks files that were changed since the last scan per workspace folder
	featureFlagService featureflag.Service
	notifier           notification.Notifier
	Instrumentor       performance.Instrumentor
	conf               configuration.Configuration
	engine             workflow.Engine
	logger             *zerolog.Logger
	configResolver     types.ConfigResolverInterface
}

func New(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, instrumentor performance.Instrumentor, apiClient snyk_api.SnykApiClient, learnService learn.Service, featureFlagService featureflag.Service, notifier notification.Notifier, configResolver types.ConfigResolverInterface) *Scanner {
	return &Scanner{
		IssueCache:         issuecache.NewIssueCache(product.ProductSecrets),
		SnykApiClient:      apiClient,
		learnService:       learnService,
		runningScans:       map[types.FilePath]*ScanStatus{},
		changedPaths:       map[types.FilePath]map[types.FilePath]bool{},
		featureFlagService: featureFlagService,
		notifier:           notifier,
		Instrumentor:       instrumentor,
		conf:               conf,
		engine:             engine,
		logger:             logger,
		configResolver:     configResolver,
	}
}

func (sc *Scanner) getConfigResolver(ctx context.Context) types.ConfigResolverInterface {
	if r, ok := ctx2.ConfigResolverFromContext(ctx); ok && r != nil {
		return r
	}
	return sc.configResolver
}

func (sc *Scanner) IsEnabledForFolder(folderConfig *types.FolderConfig) bool {
	return sc.configResolver.IsProductEnabledForFolder(sc.Product(), folderConfig)
}

func (sc *Scanner) Product() product.Product {
	return product.ProductSecrets
}

func (sc *Scanner) SupportedCommands() []types.CommandName {
	return []types.CommandName{types.NavigateToRangeCommand}
}

func (sc *Scanner) Scan(ctx context.Context, pathToScan types.FilePath) (issues []types.Issue, err error) {
	workspaceFolderConfig, ctxLogger, doScan, err := sc.checkPreconditions(ctx, pathToScan)
	if err != nil || !doScan {
		return issues, err
	}

	ctxLogger.Info().Msg("Secrets scanner: starting scan")

	folderPath := workspaceFolderConfig.FolderPath

	scanStatus := NewScanStatus()
	isAlreadyWaiting := sc.waitForScanToFinish(scanStatus, folderPath)
	if isAlreadyWaiting {
		return []types.Issue{}, nil // Returning an empty slice implies that no issues were found
	}
	defer func() {
		sc.scanStatusMutex.Lock()
		scanStatus.isRunning = false
		close(scanStatus.finished)
		sc.scanStatusMutex.Unlock()
	}()

	secretsConfig := sc.conf.Clone()
	secretsConfig.Set(configuration.ORGANIZATION, config.FolderOrganization(sc.conf, folderPath, sc.logger))

	// Determine if this is a full workspace scan or incremental file scan
	isFullWorkspaceScan := pathToScan == "" || pathToScan == folderPath

	scanPath := pathToScan
	if isFullWorkspaceScan {
		scanPath = folderPath
	}

	secretsConfig.Set(configuration.INPUT_DIRECTORY, string(scanPath))
	result, err := sc.engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("secrets.test"), secretsConfig)
	if err != nil {
		issues, err = handleSecretsInvokeError(err, ctxLogger)
		if err != nil {
			// Real error: preserve cache so previous findings remain visible during transient failures.
			return issues, err
		}
		// Ignorable error (e.g. file excluded/unsupported): preserve the existing cache
		// so previously discovered findings remain visible rather than being wiped.
		return []types.Issue{}, nil
	} else if len(result) == 1 && result[0].GetPayload() != nil {
		testApiRes := ufm.GetTestResultsFromWorkflowData(result[0])
		converter := NewFindingsConverter(ctxLogger)
		for _, res := range testApiRes {
			findings, _, findingsErr := res.Findings(ctx)
			if findingsErr != nil {
				ctxLogger.Warn().Err(findingsErr).Msg("Secrets scanner: error fetching findings")
				continue
			}
			issues = append(issues, converter.ToIssues(findings, pathToScan, folderPath)...)
		}
		ctxLogger.Info().Int("issueCount", len(issues)).Msg("Secrets scanner: scan completed")
	}

	sc.enhanceWithLearnLesson(issues)

	sc.ClearIssuesByPath(scanPath)
	sc.AddToCache(issues)
	return issues, nil
}

func (sc *Scanner) checkPreconditions(ctx context.Context, pathToScan types.FilePath) (*types.FolderConfig, *zerolog.Logger, bool, error) {
	workspaceFolderConfig, scanType, workspaceFolder, err := scannercommon.ResolveFolderAndScanType(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	l := scannercommon.LoggerWithProductScanFields(sc.logger, "secrets.Scan", pathToScan, workspaceFolder, scanType)
	ctxLogger := &l

	if err = scannercommon.RequireProductEnabled(
		sc.getConfigResolver(ctx).IsProductEnabledForFolder(sc.Product(), workspaceFolderConfig),
		utils.ErrSnykSecretsNotEnabledForFolder,
	); err != nil {
		return workspaceFolderConfig, ctxLogger, false, err
	}

	if err = scannercommon.RequireAuthToken(sc.conf, *ctxLogger); err != nil {
		return workspaceFolderConfig, ctxLogger, false, err
	}

	isSecretsScannerEnabled := workspaceFolderConfig.GetFeatureFlag(featureflag.SnykSecretsEnabled)
	if !isSecretsScannerEnabled {
		ctxLogger.Debug().Str("folderPath", string(workspaceFolder)).Msgf("feature flag %s not enabled, skipping scan", featureflag.SnykSecretsEnabled)
		return workspaceFolderConfig, ctxLogger, false, errors.New(utils.ErrSnykSecretsNotEnabled)
	}
	return workspaceFolderConfig, ctxLogger, true, nil
}

// enhanceWithLearnLesson populates each secret issue's LessonUrl from the Snyk Learn
// service. Mirrors infrastructure/code/code.go:enhanceIssuesDetails for the secrets product.
// Errors are logged and swallowed; a missing or empty lesson leaves LessonUrl untouched.
//
// Sentry-reporter parity with SAST is intentionally omitted: secrets.Scanner has no
// errorReporter field today and the rest of the package logs transient errors via the
// scanner's zerolog logger only. A non-actionable Learn-cache miss does not warrant
// expanding the constructor signature; revisit alongside any future Sentry pass on the
// secrets package.
func (sc *Scanner) enhanceWithLearnLesson(issues []types.Issue) {
	logger := sc.logger.With().Str("method", "secrets.enhanceWithLearnLesson").Logger()
	for i := range issues {
		issue := issues[i]
		lesson, err := sc.learnService.GetLesson(
			issue.GetEcosystem(), issue.GetID(),
			issue.GetCWEs(), issue.GetCVEs(),
			issue.GetIssueType(),
		)
		if err != nil {
			logger.Warn().Err(err).Str("issueId", issue.GetID()).Msg("Failed to get learn lesson")
			continue
		}
		if lesson != nil && lesson.Url != "" {
			issue.SetLessonUrl(lesson.Url)
		}
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
