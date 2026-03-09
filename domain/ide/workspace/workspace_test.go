/*
 * © 2022 Snyk Limited All rights reserved.
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

package workspace

import (
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_GetFolderTrust_shouldReturnTrustedAndUntrustedFolders(t *testing.T) {
	engine := testutil.UnitTest(t)
	const trustedDummy = types.FilePath("trustedDummy")
	const untrustedDummy = types.FilePath("untrustedDummy")
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	scanStateAggregator := scanstates.NewNoopStateAggregator()

	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	w := New(conf, logger, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	conf.Set(configuration.UserGlobalKey(types.SettingTrustEnabled), true)
	conf.Set(configuration.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{trustedDummy})
	w.AddFolder(NewFolder(conf, logger, trustedDummy, string(trustedDummy), sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine))
	w.AddFolder(NewFolder(conf, logger, untrustedDummy, string(untrustedDummy), sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine))

	trusted, untrusted := w.GetFolderTrust()

	assert.Equal(t, trustedDummy, trusted[0].Path())
	assert.Equal(t, untrustedDummy, untrusted[0].Path())
}

func Test_TrustFoldersAndScan_shouldAddFoldersToTrustedFoldersAndTriggerScan(t *testing.T) {
	engine := testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	w := New(conf, logger, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	conf.Set(configuration.UserGlobalKey(types.SettingTrustEnabled), true)
	trustedFolder := NewFolder(conf, logger, types.PathKey(trustedDummy), trustedDummy, sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	w.AddFolder(trustedFolder)
	untrustedFolder := NewFolder(conf, logger, types.PathKey(untrustedDummy), untrustedDummy, sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	w.AddFolder(untrustedFolder)

	w.TrustFoldersAndScan(t.Context(), []types.Folder{trustedFolder})

	trustedFolders, _ := engine.GetConfiguration().Get(configuration.UserGlobalKey(types.SettingTrustedFolders)).([]types.FilePath)
	assert.Contains(t, trustedFolders, trustedFolder.path)
	assert.NotContains(t, trustedFolders, untrustedFolder.path)
	assert.Eventually(t, func() bool {
		return sc.Calls() == 1
	}, time.Second, time.Millisecond, "scanner should be called after trust is granted")
}

func Test_AddAndRemoveFoldersAndReturnFolderList(t *testing.T) {
	engine := testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	const toBeRemoved = "toBeRemoved"
	trustedPathAfterConversions := uri.PathFromUri(uri.PathToUri(trustedDummy))
	toBeRemovedAbsolutePathAfterConversions := uri.PathFromUri(uri.PathToUri(toBeRemoved))
	scanStateAggregator := scanstates.NewNoopStateAggregator()

	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	w := New(conf, logger, performance.NewInstrumentor(), sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	toBeRemovedFolder := NewFolder(conf, logger, toBeRemovedAbsolutePathAfterConversions, toBeRemoved, sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	w.AddFolder(toBeRemovedFolder)

	conf.Set(configuration.UserGlobalKey(types.SettingTrustEnabled), true)
	conf.Set(configuration.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{trustedPathAfterConversions})
	conf.Set(configuration.UserGlobalKey(types.SettingScanAutomatic), true)

	params := types.DidChangeWorkspaceFoldersParams{Event: types.WorkspaceFoldersChangeEvent{
		Added: []types.WorkspaceFolder{
			{Name: trustedDummy, Uri: uri.PathToUri(trustedDummy)},
			{Name: untrustedDummy, Uri: uri.PathToUri(untrustedDummy)},
		},
		Removed: []types.WorkspaceFolder{
			{Name: toBeRemoved, Uri: uri.PathToUri(toBeRemoved)},
		},
	}}

	folderList := w.ChangeWorkspaceFolders(params)
	assert.Nil(t, w.GetFolderContaining(toBeRemoved))

	assert.Len(t, folderList, 2)
}
