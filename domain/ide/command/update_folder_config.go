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

package command

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

var (
	rescanMu     sync.Mutex
	rescanTimers = make(map[types.FilePath]*time.Timer)
)

// updateFolderConfig handles the snyk.updateFolderConfig command.
// It receives a folder path and a partial config update (PATCH semantics)
// from the tree view JS bridge, applies the update to the stored folder config,
// clears the scan cache when delta-related settings change, and triggers a rescan.
//
// This enables the HTML tree view to update folder config (e.g., base branch
// for delta scanning) without requiring the IDE to send a DidChangeConfiguration
// notification through the LSP protocol.
//
// Arguments:
//
//	args[0] = folderPath (string)
//	args[1] = configUpdate (map[string]any) — supported keys: "baseBranch", "referenceFolderPath"
type updateFolderConfig struct {
	command types.CommandData
	c       *config.Config
}

func (cmd *updateFolderConfig) Command() types.CommandData {
	return cmd.command
}

func (cmd *updateFolderConfig) Execute(ctx context.Context) (any, error) {
	folderPath, configUpdate, err := cmd.parseArgs()
	if err != nil {
		return nil, err
	}

	orig := cmd.c.FolderConfig(folderPath)
	if orig == nil {
		return nil, fmt.Errorf("no folder config found for %s", folderPath)
	}

	fc := orig.Clone()
	changed := cmd.applyConfigUpdate(fc, folderPath, configUpdate)
	if !changed {
		return true, nil
	}

	if err := cmd.c.UpdateFolderConfig(fc); err != nil {
		return nil, fmt.Errorf("failed to persist folder config: %w", err)
	}

	cmd.clearCacheAndRescan(ctx, folderPath)
	return true, nil
}

func (cmd *updateFolderConfig) parseArgs() (types.FilePath, map[string]any, error) {
	args := cmd.command.Arguments
	if len(args) < 2 {
		return "", nil, fmt.Errorf("expected 2 arguments [folderPath, configUpdate], got %d", len(args))
	}

	folderPathStr, ok := args[0].(string)
	if !ok || folderPathStr == "" {
		return "", nil, fmt.Errorf("empty folder path")
	}

	configUpdate, ok := args[1].(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("config update must be a map, got %T", args[1])
	}

	return types.FilePath(folderPathStr), configUpdate, nil
}

func (cmd *updateFolderConfig) applyConfigUpdate(
	fc *types.FolderConfig,
	folderPath types.FilePath,
	configUpdate map[string]any,
) bool {
	logger := cmd.c.Logger().With().Str("method", "updateFolderConfig.applyConfigUpdate").Logger()
	changed := false

	_, hasBranch := configUpdate["baseBranch"]
	_, hasRef := configUpdate["referenceFolderPath"]
	if hasBranch && hasRef {
		logger.Warn().Str("folderPath", string(folderPath)).
			Msg("config update contains both baseBranch and referenceFolderPath; referenceFolderPath takes precedence")
	}

	if baseBranch, exists := configUpdate["baseBranch"]; exists {
		if branchStr, ok := baseBranch.(string); ok && branchStr != fc.BaseBranch {
			logger.Info().Str("folderPath", string(folderPath)).
				Str("oldBaseBranch", fc.BaseBranch).
				Str("newBaseBranch", branchStr).
				Msg("updating base branch from tree view")
			fc.BaseBranch = branchStr
			fc.ReferenceFolderPath = ""
			changed = true
		}
	}

	if refFolder, exists := configUpdate["referenceFolderPath"]; exists {
		if refStr, ok := refFolder.(string); ok && types.FilePath(refStr) != fc.ReferenceFolderPath {
			logger.Info().Str("folderPath", string(folderPath)).
				Str("oldReferenceFolderPath", string(fc.ReferenceFolderPath)).
				Str("newReferenceFolderPath", refStr).
				Msg("updating reference folder path from tree view")
			fc.ReferenceFolderPath = types.FilePath(refStr)
			fc.BaseBranch = ""
			changed = true
		}
	}

	return changed
}

func (cmd *updateFolderConfig) clearCacheAndRescan(ctx context.Context, folderPath types.FilePath) {
	ws := cmd.c.Workspace()
	if ws == nil {
		return
	}

	folder := ws.GetFolderContaining(folderPath)
	if folder == nil {
		return
	}

	rescanMu.Lock()
	defer rescanMu.Unlock()

	if t, exists := rescanTimers[folderPath]; exists {
		t.Stop()
	}

	// Use context.WithoutCancel to preserve request-scoped values while
	// preventing the background scan from being aborted when the LSP request finishes.
	bgCtx := context.WithoutCancel(ctx)

	// Debounce rapid configuration updates (e.g. from UI toggles) to prevent
	// launching multiple concurrent full scans for the same folder.
	var timer *time.Timer
	timer = time.AfterFunc(1*time.Second, func() {
		ws.GetScanSnapshotClearerExister().ClearFolder(folderPath)
		folder.ScanFolder(bgCtx)

		rescanMu.Lock()
		if rescanTimers[folderPath] == timer {
			delete(rescanTimers, folderPath)
		}
		rescanMu.Unlock()
	})
	rescanTimers[folderPath] = timer
}
