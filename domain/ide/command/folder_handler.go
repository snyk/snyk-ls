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

	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	gitconfig "github.com/snyk/snyk-ls/internal/git_config"
	noti "github.com/snyk/snyk-ls/internal/notification"

	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/internal/types"
)

const DoTrust = "Trust folders and continue"
const DontTrust = "Don't trust folders"

func HandleFolders(ctx context.Context, srv types.Server, notifier noti.Notifier, persister persistence.ScanSnapshotPersister) {
	go sendFolderConfigsNotification(notifier)
	initScanPersister(persister)
	HandleUntrustedFolders(ctx, srv)
}

func sendFolderConfigsNotification(notifier noti.Notifier) {
	logger := config.CurrentConfig().Logger().With().Str("method", "HandleFolders").Logger()
	ws := workspace.Get()
	var folderConfigs []types.FolderConfig
	for _, f := range ws.Folders() {
		folderConfig, err := gitconfig.GetOrCreateFolderConfig(f.Path())
		if err != nil {
			logger.Warn().Err(err).Msg("error determining folder config")
			continue
		}
		folderConfigs = append(folderConfigs, *folderConfig)
	}
	folderConfigsParam := types.FolderConfigsParam{FolderConfigs: folderConfigs}
	notifier.Send(folderConfigsParam)
}

func initScanPersister(persister persistence.ScanSnapshotPersister) {
	logger := config.CurrentConfig().Logger().With().Str("method", "initScanPersister").Logger()
	w := workspace.Get()
	var folderList []string
	for _, f := range w.Folders() {
		folderList = append(folderList, f.Path())
	}
	err := persister.Init(folderList)
	if err != nil {
		logger.Error().Err(err).Msg("could not initialize scan persister")
	}
}

func HandleUntrustedFolders(ctx context.Context, srv types.Server) {
	w := workspace.Get()
	// debounce requests from overzealous clients (Eclipse, I'm looking at you)
	if w.IsTrustRequestOngoing() {
		return
	}
	w.StartRequestTrustCommunication()
	defer w.EndRequestTrustCommunication()

	_, untrusted := w.GetFolderTrust()
	if len(untrusted) > 0 {
		decision, err := showTrustDialog(srv, untrusted, DoTrust, DontTrust)
		if err != nil {
			return
		}

		if decision.Title == DoTrust {
			w.TrustFoldersAndScan(ctx, untrusted)
		}
	}
}

func showTrustDialog(srv types.Server, untrusted []*workspace.Folder, dontTrust string, doTrust string) (types.MessageActionItem, error) {
	method := "showTrustDialog"
	logger := config.CurrentConfig().Logger()
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

func GetTrustMessage(untrusted []*workspace.Folder) string {
	var untrustedFolderString string
	for _, folder := range untrusted {
		untrustedFolderString += folder.Path() + "\n"
	}
	return fmt.Sprintf("When scanning for issues, Snyk may automatically execute code such as invoking "+
		"the package manager to get dependency information. You should only scan folders you trust."+
		"\n\nUntrusted Folders: \n%s\n\n", untrustedFolderString)
}
