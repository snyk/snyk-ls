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
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/folderconfig"
	mcpWorkflow "github.com/snyk/snyk-ls/internal/mcp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	DoTrust   = "Trust folders and continue"
	DontTrust = "Don't trust folders"
)

func HandleFolders(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, ctx context.Context, srv types.Server, notifier noti.Notifier, persister persistence.ScanSnapshotPersister, agg scanstates.Aggregator, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface) {
	conf.Set(types.SettingFolderConfigsInitialized, false)
	initScanStateAggregator(conf, agg)
	initScanPersister(conf, logger, persister)
	allFoldersOK := populateAllFolderConfigs(conf, engine, logger, featureFlagService, configResolver)
	sendFolderConfigs(conf, engine, logger, notifier, featureFlagService, configResolver)
	if allFoldersOK {
		conf.Set(types.SettingFolderConfigsInitialized, true)
	} else {
		logger.Warn().Msg("folder configuration bootstrap incomplete for one or more folders; automatic scans and diagnostic republish stay disabled until HandleFolders succeeds for all folders")
	}

	HandleUntrustedFolders(ctx, conf, logger, srv)
	mcpWorkflow.CallMcpConfigWorkflow(conf, configResolver, engine, logger, notifier, false, true)
}

func populateAllFolderConfigs(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface) bool {
	if featureFlagService == nil {
		return true
	}
	ws := config.GetWorkspace(conf)
	if ws == nil {
		return true
	}
	log := logger.With().Str("method", "populateAllFolderConfigs").Logger()
	ok := true
	for _, folder := range ws.Folders() {
		fc, err := folderconfig.GetFolderConfigWithOptions(conf, folder.Path(), &log, folderconfig.GetFolderConfigOptions{
			CreateIfNotExist: true,
			EnrichFromGit:    false,
		})
		if err != nil {
			log.Err(err).Msg("unable to load folderConfig")
			ok = false
			continue
		}
		if fc == nil {
			ok = false
			continue
		}
		fc.ConfigResolver = configResolver
		featureFlagService.PopulateFolderConfig(fc)
	}
	return ok
}

func sendFolderConfigs(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, notifier noti.Notifier, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface) {
	lspConfig := BuildLspConfiguration(conf, engine, logger, featureFlagService, configResolver)
	notifier.Send(lspConfig)
}

// BuildLspConfiguration creates an LspConfigurationParam from the current config settings.
// This is the unified payload for $/snyk.configuration (protocol v25+), containing both
// global settings and per-folder settings with effective values.
// Skips write-only settings (token, sendErrorReports, etc.) per config.writeOnly annotation.
func BuildLspConfiguration(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface) types.LspConfigurationParam {
	settings := buildGlobalSettingsMap(conf, configResolver)
	return types.LspConfigurationParam{
		Settings:      settings,
		FolderConfigs: buildLspFolderConfigs(conf, engine, logger, featureFlagService, configResolver),
	}
}

// buildGlobalSettingsMap builds the global (machine- and org-scope) settings map for LS→IDE notification.
// Includes both machine-scope and org-scope settings so the IDE receives organization and product toggles.
// Uses ONLY ConfigurationOptionsMetaData + ConfigResolver. If either is nil, returns nil (empty settings).
// Skips settings with config.writeOnly annotation.
func buildGlobalSettingsMap(_ configuration.Configuration, configResolver types.ConfigResolverInterface) map[string]*types.ConfigSetting {
	if configResolver == nil {
		return nil
	}
	fm := configResolver.ConfigurationOptionsMetaData()
	if fm == nil {
		return nil
	}

	settings := make(map[string]*types.ConfigSetting)
	addScope := func(scope string) {
		for _, name := range fm.ConfigurationOptionsByAnnotation(configresolver.AnnotationScope, scope) {
			if wo, found := fm.GetConfigurationOptionAnnotation(name, configresolver.AnnotationWriteOnly); found && wo == "true" {
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

func buildLspFolderConfigs(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface) []types.LspFolderConfig {
	ws := config.GetWorkspace(conf)
	if ws == nil {
		return nil
	}
	log := logger.With().Str("method", "buildLspFolderConfigs").Logger()
	engineConfig := conf
	var lspFolderConfigs []types.LspFolderConfig

	for _, folder := range ws.Folders() {
		fc, err := folderconfig.GetOrCreateFolderConfig(engineConfig, folder.Path(), &log)
		if err != nil {
			log.Err(err).Msg("unable to load folderConfig")
			continue
		}

		if fc == nil {
			log.Warn().Str("path", string(folder.Path())).Msg("folder config is nil, skipping")
			continue
		}
		folderConfig := fc.Clone()

		// AutoDeterminedOrg is written to FolderMetadataKey by LDX-Sync (SetAutoDeterminedOrg);
		// no separate cache lookup is needed here.

		folderConfig.ConfigResolver = configResolver
		lspConfig := folderConfig.ToLspFolderConfig()
		if lspConfig != nil {
			lspFolderConfigs = append(lspFolderConfigs, *lspConfig)
		}
	}

	return lspFolderConfigs
}

func initScanStateAggregator(conf configuration.Configuration, agg scanstates.Aggregator) {
	w := config.GetWorkspace(conf)
	if w == nil {
		return
	}
	var folderPaths []types.FilePath
	for _, f := range w.Folders() {
		folderPaths = append(folderPaths, f.Path())
	}
	agg.Init(folderPaths)
}

func initScanPersister(conf configuration.Configuration, logger *zerolog.Logger, persister persistence.ScanSnapshotPersister) {
	log := logger.With().Str("method", "initScanPersister").Logger()
	w := config.GetWorkspace(conf)
	if w == nil {
		return
	}
	var folderList []types.FilePath
	for _, f := range w.Folders() {
		folderList = append(folderList, f.Path())
	}
	err := persister.Init(folderList)
	if err != nil {
		log.Error().Err(err).Msg("could not initialize scan persister")
	}
}

func HandleUntrustedFolders(ctx context.Context, conf configuration.Configuration, logger *zerolog.Logger, srv types.Server) {
	w := config.GetWorkspace(conf)
	if w == nil {
		return
	}
	// debounce requests from overzealous clients (Eclipse, I'm looking at you)
	if w.IsTrustRequestOngoing() {
		return
	}
	_, untrusted := w.GetFolderTrust()
	if len(untrusted) > 0 {
		go func() {
			w.StartRequestTrustCommunication()
			defer w.EndRequestTrustCommunication()
			decision, err := showTrustDialog(logger, srv, untrusted, DoTrust, DontTrust)
			if err != nil {
				return
			}
			if decision.Title == DoTrust {
				w.TrustFoldersAndScan(ctx, untrusted)
			}
		}()
	}
}

func showTrustDialog(logger *zerolog.Logger, srv types.Server, untrusted []types.Folder, dontTrust string, doTrust string) (types.MessageActionItem, error) {
	method := "showTrustDialog"
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
