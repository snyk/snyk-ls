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
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/domain/snyk"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/issuecache"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
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
	scanStatusMutex    sync.RWMutex
	runningScans       map[types.FilePath]*ScanStatus
	changedPaths       map[types.FilePath]map[types.FilePath]bool // tracks files that were changed since the last scan per workspace folder
	featureFlagService featureflag.Service
	notifier           notification.Notifier
	Instrumentor       performance.Instrumentor
	C                  *config.Config
	configResolver     types.ConfigResolverInterface
}

func New(c *config.Config, instrumentor performance.Instrumentor, apiClient snyk_api.SnykApiClient, featureFlagService featureflag.Service, notifier notification.Notifier, configResolver types.ConfigResolverInterface) *Scanner {
	return &Scanner{
		IssueCache:         issuecache.NewIssueCache(product.ProductSecrets),
		SnykApiClient:      apiClient,
		runningScans:       map[types.FilePath]*ScanStatus{},
		changedPaths:       map[types.FilePath]map[types.FilePath]bool{},
		featureFlagService: featureFlagService,
		notifier:           notifier,
		Instrumentor:       instrumentor,
		C:                  c,
		configResolver:     configResolver,
	}
}

func (sc *Scanner) IsEnabledForFolder(folderConfig *types.FolderConfig) bool {
	return types.ResolveIsProductEnabledForFolder(sc.configResolver, sc.C, sc.Product(), folderConfig)
}

func (sc *Scanner) Product() product.Product {
	return product.ProductSecrets
}

func (sc *Scanner) SupportedCommands() []types.CommandName {
	return []types.CommandName{types.NavigateToRangeCommand}
}

func (sc *Scanner) Scan(ctx context.Context, pathToScan types.FilePath, workspaceFolderConfig *types.FolderConfig) (issues []types.Issue, err error) {
	// Log scan type and paths
	scanType := "WorkingDirectory"
	if deltaScanType, ok := ctx2.DeltaScanTypeFromContext(ctx); ok {
		scanType = deltaScanType.String()
	}

	workspaceFolder := workspaceFolderConfig.FolderPath

	logger := sc.C.Logger().With().
		Str("method", "secrets.Scan").
		Str("path", string(pathToScan)).
		Str("folderPath", string(workspaceFolder)).
		Str("scanType", scanType).
		Logger()

	logger.Debug().Msg("Secrets scanner: starting scan")

	if !sc.C.NonEmptyToken() {
		logger.Info().Msg("not authenticated, not scanning")
		return issues, err
	}

	isSecretsScannerEnabled := workspaceFolderConfig.FeatureFlags[featureflag.SnykSecretsEnabled]
	if !isSecretsScannerEnabled {
		logger.Error().Str("folderPath", string(workspaceFolder)).Msgf("feature flag %s not enabled", featureflag.SnykSecretsEnabled)
		return issues, errors.New("feature flag not found")
	}

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

	secretsConfig := sc.C.Engine().GetConfiguration().Clone()
	secretsConfig.Set(configuration.ORGANIZATION, sc.C.FolderOrganization(workspaceFolder))

	// Determine if this is a full workspace scan or incremental file scan
	isFullWorkspaceScan := pathToScan == "" || pathToScan == workspaceFolder

	scanPath := pathToScan
	if isFullWorkspaceScan {
		scanPath = workspaceFolder
	}

	secretsConfig.Set(configuration.INPUT_DIRECTORY, string(scanPath))
	result, err := sc.C.Engine().InvokeWithConfig(workflow.NewWorkflowIdentifier("secrets.test"), secretsConfig)
	if err != nil {
		return nil, err
	}
	if len(result) == 1 && result[0].GetPayload() != nil {
		testApiRes := ufm.GetTestResultsFromWorkflowData(result[0])
		converter := NewFindingsConverter(&logger)
		for _, res := range testApiRes {
			findings, _, findingsErr := res.Findings(ctx)
			if findingsErr != nil {
				logger.Warn().Err(findingsErr).Msg("Secrets scanner: error fetching findings")
				continue
			}
			issues = append(issues, converter.ToIssues(findings, pathToScan, workspaceFolder)...)
		}
		logger.Debug().Int("issueCount", len(issues)).Msg("Secrets scanner: scan completed")
	}

	sc.ClearByIssueSlice(issues)
	sc.AddToCache(issues)
	return issues, err
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
