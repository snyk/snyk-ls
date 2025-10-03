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

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/storedconfig"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

const DoTrust = "Trust folders and continue"
const DontTrust = "Don't trust folders"

func HandleFolders(c *config.Config, ctx context.Context, srv types.Server, notifier noti.Notifier, persister persistence.ScanSnapshotPersister, agg scanstates.Aggregator) {
	initScanStateAggregator(c, agg)
	initScanPersister(c, persister)
	// send folder configs (they are queued until initialization is done)
	go sendFolderConfigs(c, notifier)
	HandleUntrustedFolders(ctx, c, srv)
}

func sendFolderConfigs(c *config.Config, notifier noti.Notifier) {
	logger := c.Logger().With().Str("method", "sendFolderConfigs").Logger()
	configuration := c.Engine().GetConfiguration()

	var folderConfigs []types.FolderConfig
	for _, folder := range c.Workspace().Folders() {
		storedConfig, err2 := storedconfig.GetOrCreateFolderConfig(configuration, folder.Path(), &logger)
		if err2 != nil {
			logger.Err(err2).Msg("unable to load stored config")
			return
		}

		UpdateFolderConfigOrg(c, storedConfig, nil)

		folderConfigs = append(folderConfigs, *storedConfig)
	}

	if folderConfigs == nil {
		return
	}

	folderConfigsParam := types.FolderConfigsParam{FolderConfigs: folderConfigs}
	notifier.Send(folderConfigsParam)
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

func UpdateFolderConfigOrg(c *config.Config, storedConfig *types.FolderConfig, folderConfig *types.FolderConfig) {
	// For configs that have been migrated, we use the org returned by LDX-Sync unless the user has set one.
	if storedConfig.OrgMigratedFromGlobalConfig {
		if folderConfig == nil {
			// Language server is initializing, or processing added/removed folders (workspace/didChangeWorkspaceFolders)
			// We are only dealing with stored configs (new configs will not have been migrated yet).
			// We should look up the org from LDX-Sync if EITHER:
			// 1. The org is not set by the user
			// 2. The org is now being inherited from a blank global org.
			orgInheritingFromBlankGlobal := storedConfig.Organization == "" && c.Organization() == ""
			if !storedConfig.OrgSetByUser || orgInheritingFromBlankGlobal {
				setOrgFromLdxSync(c, storedConfig)
				storedConfig.OrgSetByUser = false
			}
			return
		}

		orgInheritingFromBlankGlobal := folderConfig.Organization == "" && c.Organization() == ""
		orgHasJustChanged := folderConfig.Organization != storedConfig.Organization

		if orgInheritingFromBlankGlobal || !folderConfig.OrgSetByUser {
			// The user is either:
			// 1. blanking their folder config org while they don't have a global org set
			// 2. blanking their global org while they don't have a folder config org set
			// 3. explicitly opting in to LDX-Sync.
			setOrgFromLdxSync(c, storedConfig)
			storedConfig.OrgSetByUser = false
		} else if orgHasJustChanged || folderConfig.OrgSetByUser {
			// Store the user-provided org.
			// We have already checked that the user wishes to provide an org and the org is valid or can inherit a valid org.
			storedConfig.Organization = folderConfig.Organization
			storedConfig.OrgSetByUser = true
		}
	} else {
		migrateFolderConfigOrg(c, storedConfig, folderConfig)
	}
}

func migrateFolderConfigOrg(c *config.Config, storedConfig *types.FolderConfig, folderConfig *types.FolderConfig) {
	// If we are migrating a folderConfig provided by the user, we simply save it and skip LDX-Sync lookup,
	// unless they are trying to inherit a blank global org.
	if folderConfig != nil && (folderConfig.Organization != "" || (folderConfig.OrgSetByUser && c.Organization() != "")) {
		storedConfig.Organization = folderConfig.Organization
		storedConfig.OrgSetByUser = folderConfig.OrgSetByUser
		storedConfig.OrgMigratedFromGlobalConfig = true
		return
	}

	// If the folder config does not have an org, we should use the globally set org.
	storedConfig.Organization = c.Organization()

	// Call LDX-Sync to resolve the org.
	newOrgIsDefault := setOrgFromLdxSync(c, storedConfig)

	// If LDX-Sync returns a different org, we should mark it as not set by the user.
	if storedConfig.Organization != c.Organization() || newOrgIsDefault {
		storedConfig.OrgSetByUser = false
	} else {
		// The folder is using same org as the global config. We mark this as user set unless it matches the
		// default org.
		storedConfig.Organization = ""
		storedConfig.OrgSetByUser = true
	}

	storedConfig.OrgMigratedFromGlobalConfig = true
}

func setOrgFromLdxSync(c *config.Config, storedConfig *types.FolderConfig) (newOrgIsDefault bool) {
	logger := c.Logger().With().Str("method", "updateAndSendFolderConfigs").Logger()

	path := storedConfig.FolderPath

	newOrg, err := ldx_sync_config.ResolveOrganization(c.Engine().GetConfiguration(), c.Engine(), &logger, string(path), storedConfig.Organization)
	if err != nil {
		logger.Err(err).Msg("unable to resolve organization")
	} else {
		storedConfig.Organization = newOrg.Id
	}
	newOrgIsDefaultPtr := newOrg.IsDefault
	return newOrgIsDefaultPtr != nil && *newOrgIsDefaultPtr
}
