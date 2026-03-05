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

package command

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/pkg/errors"

	mcpWorkflow "github.com/snyk/snyk-ls/internal/mcp"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	DoTrust   = "Trust folders and continue"
	DontTrust = "Don't trust folders"
)

func HandleFolders(c *config.Config, ctx context.Context, srv types.Server, notifier noti.Notifier, persister persistence.ScanSnapshotPersister, agg scanstates.Aggregator, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface) {
	initScanStateAggregator(c, agg)
	initScanPersister(c, persister)
	sendFolderConfigs(c, notifier, featureFlagService, configResolver)

	HandleUntrustedFolders(ctx, c, srv)
	mcpWorkflow.CallMcpConfigWorkflow(c, notifier, false, true)
}

func sendFolderConfigs(c *config.Config, notifier noti.Notifier, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface) {
	lspConfig := BuildLspConfiguration(c, featureFlagService, configResolver)
	notifier.Send(lspConfig)
}

// BuildLspConfiguration creates an LspConfigurationParam from the current config settings.
// This is the unified payload for $/snyk.configuration (protocol v25+), containing both
// global settings and per-folder settings with effective values.
// Skips write-only settings (token, sendErrorReports, etc.) per config.writeOnly annotation.
func BuildLspConfiguration(c *config.Config, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface) types.LspConfigurationParam {
	settings := buildGlobalSettingsMap(c, configResolver)
	return types.LspConfigurationParam{
		Settings:      settings,
		FolderConfigs: buildLspFolderConfigs(c, featureFlagService, configResolver),
	}
}

// buildGlobalSettingsMap builds the global (machine- and org-scope) settings map for LS→IDE notification.
// Includes both machine-scope and org-scope settings so the IDE receives organization and product toggles.
// Uses ONLY FlagMetadata + ConfigResolver. If either is nil, returns nil (empty settings).
// Skips settings with config.writeOnly annotation.
func buildGlobalSettingsMap(c *config.Config, configResolver types.ConfigResolverInterface) map[string]*types.ConfigSetting {
	conf := c.Engine().GetConfiguration()
	fm, hasFM := conf.(configuration.FlagMetadata)
	if !hasFM || configResolver == nil {
		return nil
	}

	settings := make(map[string]*types.ConfigSetting)
	addScope := func(scope string) {
		for _, name := range fm.FlagsByAnnotation(configuration.AnnotationScope, scope) {
			if wo, found := fm.GetFlagAnnotation(name, configuration.AnnotationWriteOnly); found && wo == "true" {
				continue
			}
			ev := configResolver.GetEffectiveValue(name, nil)
			// Only send organization when we have a resolved value (e.g. after LDX-Sync or default org resolution)
			if name == types.SettingOrganization && (ev.Value == nil || ev.Value == "") {
				continue
			}
			settings[name] = &types.ConfigSetting{
				Value:       ev.Value,
				Source:      ev.Source,
				OriginScope: ev.OriginScope,
				IsLocked:    strings.Contains(ev.Source, "locked"),
			}
		}
	}
	addScope("machine")
	addScope("org")
	return settings
}

func buildLspFolderConfigs(c *config.Config, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface) []types.LspFolderConfig {
	ws := c.Workspace()
	if ws == nil {
		return nil
	}
	logger := c.Logger().With().Str("method", "buildLspFolderConfigs").Logger()
	engineConfig := c.Engine().GetConfiguration()
	var lspFolderConfigs []types.LspFolderConfig

	for _, folder := range ws.Folders() {
		storedFolderConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folder.Path(), &logger)
		if err != nil {
			logger.Err(err).Msg("unable to load stored config")
			continue
		}

		folderConfig := storedFolderConfig.Clone()

		if featureFlagService != nil {
			featureFlagService.PopulateFolderConfig(folderConfig)
		}

		cache := c.GetLdxSyncOrgConfigCache()
		if orgId := cache.GetOrgIdForFolder(folderConfig.FolderPath); orgId != "" {
			types.SetAutoDeterminedOrg(engineConfig, folderConfig.FolderPath, orgId)
		}

		applyChanged := storedFolderConfig == nil
		if !applyChanged {
			oldSnap := types.ReadFolderConfigSnapshot(engineConfig, storedFolderConfig.FolderPath)
			newSnap := types.ReadFolderConfigSnapshot(engineConfig, folderConfig.FolderPath)
			applyChanged = !folderConfigSnapshotsEqual(oldSnap, newSnap)
		}
		if applyChanged {
			if err := storedconfig.UpdateFolderConfig(engineConfig, folderConfig, &logger); err != nil {
				logger.Err(err).Msg("unable to save folder config")
			}
		}

		folderConfig.ConfigResolver = configResolver
		lspConfig := folderConfig.ToLspFolderConfig()
		if lspConfig != nil {
			lspFolderConfigs = append(lspFolderConfigs, *lspConfig)
		}
	}

	return lspFolderConfigs
}

// folderConfigSnapshotsEqual compares two snapshots for equality (used to detect config changes).
func folderConfigSnapshotsEqual(a, b types.FolderConfigSnapshot) bool {
	return a.BaseBranch == b.BaseBranch &&
		reflect.DeepEqual(a.LocalBranches, b.LocalBranches) &&
		reflect.DeepEqual(a.AdditionalParameters, b.AdditionalParameters) &&
		a.AdditionalEnv == b.AdditionalEnv &&
		a.ReferenceFolderPath == b.ReferenceFolderPath &&
		reflect.DeepEqual(a.ScanCommandConfig, b.ScanCommandConfig) &&
		a.PreferredOrg == b.PreferredOrg &&
		a.AutoDeterminedOrg == b.AutoDeterminedOrg &&
		a.OrgSetByUser == b.OrgSetByUser &&
		reflect.DeepEqual(a.UserOverrides, b.UserOverrides)
}

func initScanStateAggregator(c *config.Config, agg scanstates.Aggregator) {
	var folderPaths []types.FilePath
	for _, f := range c.Workspace().Folders() {
		folderPaths = append(folderPaths, f.Path())
	}
	agg.Init(folderPaths)
}

func initScanPersister(c *config.Config, persister persistence.ScanSnapshotPersister) {
	logger := c.Logger().With().Str("method", "initScanPersister").Logger()
	w := c.Workspace()
	var folderList []types.FilePath
	for _, f := range w.Folders() {
		folderList = append(folderList, f.Path())
	}
	err := persister.Init(folderList)
	if err != nil {
		logger.Error().Err(err).Msg("could not initialize scan persister")
	}
}

func HandleUntrustedFolders(ctx context.Context, c *config.Config, srv types.Server) {
	w := c.Workspace()
	// debounce requests from overzealous clients (Eclipse, I'm looking at you)
	if w.IsTrustRequestOngoing() {
		return
	}
	_, untrusted := w.GetFolderTrust()
	if len(untrusted) > 0 {
		go func() {
			w.StartRequestTrustCommunication()
			defer w.EndRequestTrustCommunication()
			decision, err := showTrustDialog(c, srv, untrusted, DoTrust, DontTrust)
			if err != nil {
				return
			}
			if decision.Title == DoTrust {
				w.TrustFoldersAndScan(ctx, untrusted)
			}
		}()
	}
}

func showTrustDialog(c *config.Config, srv types.Server, untrusted []types.Folder, dontTrust string, doTrust string) (types.MessageActionItem, error) {
	method := "showTrustDialog"
	logger := c.Logger()
	result, err := srv.Callback(context.Background(), "window/showMessageRequest", types.ShowMessageRequestParams{
		Type:    types.Warning,
		Message: GetTrustMessage(untrusted),
		Actions: []types.MessageActionItem{{Title: dontTrust}, {Title: doTrust}},
	})
	if err != nil {
		logger.Err(errors.Wrap(err, "couldn't show trust message")).Str("method", method).Send()
		return types.MessageActionItem{Title: dontTrust}, err
	}

	var trust types.MessageActionItem
	if result != nil {
		err = result.UnmarshalResult(&trust)
		if err != nil {
			logger.Err(errors.Wrap(err, "couldn't unmarshal trust message")).Str("method", method).Send()
			return types.MessageActionItem{Title: dontTrust}, err
		}
	}
	return trust, err
}

func GetTrustMessage(untrusted []types.Folder) string {
	var untrustedFolderString types.FilePath
	for _, folder := range untrusted {
		untrustedFolderString += folder.Path() + "\n"
	}
	return fmt.Sprintf("When scanning for issues, Snyk may automatically execute code such as invoking "+
		"the package manager to get dependency information. You should only scan folders you trust."+
		"\n\nUntrusted Folders: \n%s\n\n", untrustedFolderString)
}
