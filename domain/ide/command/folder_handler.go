/*
 * © 2023 Snyk Limited
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

	"github.com/pkg/errors"

	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	DoTrust   = "Trust folders and continue"
	DontTrust = "Don't trust folders"
)

func HandleFolders(c *config.Config, ctx context.Context, srv types.Server, notifier noti.Notifier, persister persistence.ScanSnapshotPersister, agg scanstates.Aggregator) {
	initScanStateAggregator(c, agg)
	initScanPersister(c, persister)
	// send folder configs (they are queued until initialization is done)
	go sendFolderConfigs(c, notifier)
	HandleUntrustedFolders(ctx, c, srv)
}

func sendFolderConfigs(c *config.Config, notifier noti.Notifier) {
	logger := c.Logger().With().Str("method", "sendFolderConfigs").Logger()
	gafConfig := c.Engine().GetConfiguration()

	var folderConfigs []types.FolderConfig
	for _, folder := range c.Workspace().Folders() {
		folderConfig, err2 := storedconfig.GetOrCreateFolderConfig(gafConfig, folder.Path(), &logger)
		if err2 != nil {
			logger.Err(err2).Msg("unable to load stored config")
			return
		}

		changedFolderConfig := false

		// Always update AutoDeterminedOrg from LDX-Sync (even for folders where OrgSetByUser is true)
		// This ensures we always know what LDX-Sync recommends, regardless of whether the user has opted out
		org, err := GetBestOrgFromLdxSync(c, folderConfig)
		if err != nil {
			logger.Err(err).Msg("unable to resolve organization, continuing...")
		} else {
			folderConfig.AutoDeterminedOrg = org.Id
			changedFolderConfig = true
		}

		// Trigger migration for folders that haven't been migrated yet
		// This ensures that folders loaded from storage get migrated on initialization
		if !folderConfig.OrgMigratedFromGlobalConfig {
			MigrateFolderConfigOrgSettings(c, folderConfig)
			changedFolderConfig = true
		}

		if changedFolderConfig {
			// Save the migrated folder config back to storage
			err = storedconfig.UpdateFolderConfig(gafConfig, folderConfig, &logger)
			if err != nil {
				logger.Err(err).Msg("unable to save migrated folder config")
			}
		}

		folderConfigs = append(folderConfigs, *folderConfig)
	}

	if folderConfigs == nil {
		return
	}
	folderConfigsParam := types.FolderConfigsParam{FolderConfigs: folderConfigs}
	notifier.Send(folderConfigsParam)
}

func GetBestOrgFromLdxSync(c *config.Config, folderConfig *types.FolderConfig) (ldx_sync_config.Organization, error) {
	engine := c.Engine()
	gafConfig := engine.GetConfiguration()

	return OrganizationResolver().ResolveOrganization(gafConfig, engine, c.Logger(), string(folderConfig.FolderPath))
}

// MigrateFolderConfigOrgSettings applies the organization settings to a folder config during migration
// based on the global organization setting and the LDX-Sync result.
func MigrateFolderConfigOrgSettings(c *config.Config, folderConfig *types.FolderConfig) {
	// Edge case when user provided folder config on initialize params or
	// the user is changing settings while unauthenticated
	if folderConfig.OrgSetByUser {
		// we take what they set and simply save it as migrated.
		folderConfig.OrgMigratedFromGlobalConfig = true
		return
	} else if folderConfig.PreferredOrg != "" {
		// they may have just changed the preferred org field while unauthenticated, still treat it as opting out of auto-org
		// or provided initialize params had Preferred org defined but OrgSetByUser = false, so we fix it
		folderConfig.OrgSetByUser = true
		folderConfig.OrgMigratedFromGlobalConfig = true
		return
	}

	globalOrg := c.Organization()

	// Check if the configured organization is the default org
	isDefaultOrUnknown, err := isOrgDefault(c, globalOrg)
	if err != nil {
		c.Logger().Err(err).Msg("unable to determine if organization is default")
		return
	}

	// Determine OrgSetByUser based on whether the org is the default (or an unknown slug)
	// - Using default org, so not set by user, or has an unknown slug, either way opt them in to LDX-Sync.
	// - Using a non-default org, so it was explicitly set by user, so opt them out of LDX-Sync.
	folderConfig.OrgSetByUser = !isDefaultOrUnknown

	// We decided to write the global org as-is into the PreferredOrg on migration, if the user is not using LDX-Sync.
	if folderConfig.OrgSetByUser {
		folderConfig.PreferredOrg = globalOrg
	}

	folderConfig.OrgMigratedFromGlobalConfig = true
}

// isOrgDefault Returns true if the org provided is either:
// 1. an empty string
// 2. the same UUID as the user's default org
// 3. the same slug as the user's default org
func isOrgDefault(c *config.Config, organization string) (bool, error) {
	if organization == "" {
		return true, nil
	}

	clonedGAFConfig := c.Engine().GetConfiguration().Clone()
	clonedGAFConfig.Set(configuration.ORGANIZATION, "")
	defaultOrgUUID := clonedGAFConfig.GetString(configuration.ORGANIZATION)
	if defaultOrgUUID == "" {
		return false, fmt.Errorf("could not retrieve the user's default organization")
	}
	if organization == defaultOrgUUID {
		return true, nil
	}

	defaultOrgSlug := clonedGAFConfig.GetString(configuration.ORGANIZATION_SLUG)
	if defaultOrgSlug == "" {
		return false, fmt.Errorf("could not retrieve the user's default organization slug")
	}
	if organization == defaultOrgSlug {
		return true, nil
	}

	return false, nil
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
