/*
 * Copyright 2022 Snyk Ltd.
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

package server

import (
	"context"
	"fmt"

	"github.com/creachadair/jrpc2"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
)

const doTrust = "Trust folders and continue"
const dontTrust = "Don't trust folders"

func handleUntrustedFolders(ctx context.Context, srv *jrpc2.Server) {
	w := workspace.Get()
	// debounce requests from overzealous clients (Eclipse, I'm looking at you)
	if w.IsTrustRequestOngoing() {
		return
	}
	w.StartRequestTrustCommunication()
	defer w.EndRequestTrustCommunication()

	_, untrusted := w.GetFolderTrust()
	if len(untrusted) > 0 {

		decision, err := showTrustDialog(srv, untrusted, doTrust, dontTrust)
		if err != nil {
			return
		}

		if decision.Title == doTrust {
			w.TrustFoldersAndScan(ctx, untrusted)
		}
	}
}

func showTrustDialog(srv *jrpc2.Server, untrusted []*workspace.Folder, dontTrust string, doTrust string) (lsp.MessageActionItem, error) {
	method := "showTrustDialog"
	result, err := srv.Callback(context.Background(), "window/showMessageRequest", lsp.ShowMessageRequestParams{
		Type:    lsp.Warning,
		Message: getTrustMessage(untrusted),
		Actions: []lsp.MessageActionItem{{Title: dontTrust}, {Title: doTrust}},
	})
	if err != nil {
		log.Err(errors.Wrap(err, "couldn't show trust message")).Str("method", method).Send()
		return lsp.MessageActionItem{Title: dontTrust}, err
	}

	var trust lsp.MessageActionItem
	if result != nil {
		err = result.UnmarshalResult(&trust)
		if err != nil {
			log.Err(errors.Wrap(err, "couldn't unmarshal trust message")).Str("method", method).Send()
			return lsp.MessageActionItem{Title: dontTrust}, err
		}
	}
	return trust, err
}

func getTrustMessage(untrusted []*workspace.Folder) string {
	var untrustedFolderString string
	for _, folder := range untrusted {
		untrustedFolderString += folder.Path() + "\n"
	}
	return fmt.Sprintf("When scanning for vulnerabilities, Snyk may automatically execute code such as invoking "+
		"the package manager to get dependency information. You should only scan folders you trust."+
		"\n\nUntrusted Folders: \n%s\n\n", untrustedFolderString)
}
