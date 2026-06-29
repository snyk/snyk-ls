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

// Package remediation defines the interface and implementations for
// autonomous finding remediation.
package remediation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/types"
)

// remyRunner is the seam that lets tests inject a fake runner without shelling
// out to a real CLI. The real implementation invokes the legacycli workflow
// via the Go Application Framework engine.
//
// eng is the workflow engine used for GAF invocation (nil in tests).
// contentRoot is the absolute path of the git worktree to operate on.
// findingID is the stable identifier of the finding to fix.
type remyRunner func(ctx context.Context, eng workflow.Engine, contentRoot string, findingID string) error

// RemyOptions controls the behavior of the concrete remy-backed provider.
type RemyOptions struct {
	// Timeout caps how long a single remediation attempt may run. When zero,
	// a 5-minute default applies.
	Timeout time.Duration
}

// remyCacheEntry holds the changes produced by a single remy run that have not
// yet been delivered to a code action. Entries are keyed by absolute workspace
// path. fileHashes records, for each cached file path, the SHA-256 of the
// pre-run HEAD content the cached edits were computed against.
// tryServeFromCache hashes the current file and compares it against this
// baseline to detect any modification — including a concurrent user edit made
// while remy was still running — independently of filesystem mtime granularity.
type remyCacheEntry struct {
	changes    map[string][]types.TextEdit
	fileHashes map[string]string // abs path → hex SHA-256 of pre-run HEAD content
}

// remyProvider is the concrete RemediationProvider that drives the host snyk
// binary's remy subcommand to apply an LLM-generated fix and translates the
// resulting file changes into a WorkspaceEdit.
type remyProvider struct {
	opts   RemyOptions
	runner remyRunner
	engine workflow.Engine
	log    zerolog.Logger

	cacheMu sync.Mutex
	cache   map[string]*remyCacheEntry // ContentRoot → leftover changes from last run

	// rootMusMu protects rootMus. rootMus holds one mutex per ContentRoot so
	// that concurrent Remediate calls for different roots run in parallel while
	// calls for the same root are serialized, preventing double remy invocations.
	rootMusMu sync.Mutex
	rootMus   map[string]*sync.Mutex
}

// Ensure remyProvider satisfies all interfaces at compile time.
var _ RemediationProvider = (*remyProvider)(nil)
var _ FileChangeNotifier = (*remyProvider)(nil)
var _ FolderRemediator = (*remyProvider)(nil)

// gafRunner is the default remyRunner that invokes the legacycli workflow via
// the Go Application Framework engine. The remy fix workflow is a Go extension
// registered under the "fix" workflow ID — invoke it directly, not via legacycli.
// auto-approve suppresses interactive prompts required for non-interactive LS use.
func gafRunner(ctx context.Context, eng workflow.Engine, contentRoot string, _ string) error {
	remyWorkflowID := workflow.NewWorkflowIdentifier("fix")
	conf := eng.GetConfiguration().Clone()
	conf.Set("agentic", true)
	conf.Set("auto-approve", true)
	conf.Set(configuration.INPUT_DIRECTORY, []string{contentRoot})
	_, err := eng.Invoke(remyWorkflowID, workflow.WithContext(ctx), workflow.WithConfig(conf))
	return err
}

// NewRemyProvider constructs a remyProvider.
//
// engine is the workflow engine used for GAF invocation.
// runner is the test seam; pass nil to use the default gafRunner which
// invokes the legacycli workflow via the engine. Callers that want to plug
// in a fake runner for unit tests pass a non-nil function here.
func NewRemyProvider(engine workflow.Engine, runner remyRunner) RemediationProvider {
	if runner == nil && engine == nil {
		panic("NewRemyProvider: nil runner requires a non-nil engine; pass a test runner or a workflow.Engine")
	}
	var log zerolog.Logger
	opts := RemyOptions{}
	if engine != nil {
		l := engine.GetLogger().With().Str("provider", "remy").Logger()
		log = l
	} else {
		log = zerolog.Nop()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}
	if runner == nil {
		runner = gafRunner
	}
	return &remyProvider{opts: opts, runner: runner, engine: engine, log: log, cache: make(map[string]*remyCacheEntry), rootMus: make(map[string]*sync.Mutex)}
}

// getOrCreateRootMu returns the per-ContentRoot mutex, creating it if needed.
// Serializing remy invocations per root prevents concurrent callers from
// both missing the cache and launching duplicate LLM calls.
func (p *remyProvider) getOrCreateRootMu(root string) *sync.Mutex {
	p.rootMusMu.Lock()
	defer p.rootMusMu.Unlock()
	if mu, ok := p.rootMus[root]; ok {
		return mu
	}
	mu := &sync.Mutex{}
	p.rootMus[root] = mu
	return mu
}

// tryServeFromCache looks up the cache for root/filePath while holding p.cacheMu
// only around map access, never during file I/O. It first confirms the entry
// exists and filePath is present — an absent filePath is an immediate miss with
// no I/O. It then reads only filePath's stored hash, RELEASES the lock, and
// hashes filePath's current content off-lock so that a concurrent InvalidateFile
// (LSP didChange) is never blocked waiting for disk I/O.
//
// Sibling staleness is intentionally not checked here: validating all cached
// files and evicting the whole root on any mismatch causes over-eviction — a
// concurrent InvalidateFile that correctly removes a sibling would appear stale
// in a pre-lock snapshot and destroy still-valid siblings. Each sibling is
// validated only when it is itself served; InvalidateFile handles LSP-driven
// invalidation.
//
// After hashing, re-acquires the lock and re-checks the entry is still present
// and unchanged (pointer equality guards against a concurrent remy run replacing
// the entry) and filePath is still present (guards concurrent InvalidateFile).
//
// The hash outcome drives five distinct behaviors, checked in this order:
//
//  1. hashErr is fs.ErrNotExist (the file is GONE): the cached edits target
//     content that no longer exists, so the entry is invalid. Consume filePath
//     from both maps (evict when empty) and return (nil, false) so Remediate
//     re-runs the runner — identical handling to a genuine content mismatch.
//
//  2. hashErr != nil, but NOT not-exist (the file EXISTS yet is momentarily
//     unreadable — briefly locked by AV/IDE, a permission blip, or is-a-directory):
//     this is transient. Leave the entry COMPLETELY intact, emit a debug log, and
//     return (nil, true). The true signals Remediate to skip the runner (which
//     would replace the preserved entry) and return (nil, nil) to the LSP client,
//     which will retry on the next code action. Evicting or running the runner on
//     a transient error would permanently discard a valid multi-minute remy result
//     and force an unnecessary re-run.
//
//  3. storedHash == "" (hash was not recorded at populate time — unreachable with
//     the current hashBytes path, but guarded defensively): return (nil, false)
//     WITHOUT consuming the entry. If we consumed and evicted without being able
//     to validate, we would destroy valid edits unnecessarily.
//
//  4. curHash != storedHash (genuine content change confirmed): consume filePath
//     from both maps (dual-map delete to keep maps in sync), evict when empty,
//     return (nil, false) — genuine miss, caller runs the runner.
//
//  5. curHash == storedHash (content unchanged): consume filePath and return
//     (edits, true).
//
// Cases 1 (not-exist), 4 (mismatch) and 5 (match) consume the entry; cases 2
// (transient) and 3 (empty baseline) leave it intact.
//
// In summary: gone/not-exist → miss, consume (re-run); transient other error →
// preserve, suppress re-run; empty baseline → miss, no consume; mismatch → miss,
// consume; match → hit, consume.
//
// Returns (edits, true) on a valid hit, (nil, true) on a transient I/O error
// (entry preserved, runner must not fire), and (nil, false) on a genuine miss.
func (p *remyProvider) tryServeFromCache(root, filePath string) ([]types.TextEdit, bool) {
	p.cacheMu.Lock()
	entry, exists := p.cache[root]
	if !exists {
		p.cacheMu.Unlock()
		return nil, false
	}
	if _, ok := entry.changes[filePath]; !ok {
		// filePath is not in this entry — miss without hashing any files.
		p.cacheMu.Unlock()
		return nil, false
	}
	// Only snapshot filePath's own hash. Checking sibling hashes here causes
	// over-eviction (see doc comment above).
	storedHash := entry.fileHashes[filePath]
	original := entry
	p.cacheMu.Unlock()

	// Hash the current workspace file off-lock so InvalidateFile is never blocked.
	curHash, hashErr := fileHash(filePath)

	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	entry, exists = p.cache[root]
	if !exists || entry != original {
		// Entry was evicted or replaced by a concurrent remy run while off-lock.
		return nil, false
	}
	if _, ok := entry.changes[filePath]; !ok {
		// filePath was invalidated by a concurrent InvalidateFile while off-lock.
		return nil, false
	}
	if hashErr != nil {
		if errors.Is(hashErr, fs.ErrNotExist) {
			// The file is gone — cached edits target content that no longer exists.
			// Consume filePath from both maps (evict when empty) and return a miss
			// so Remediate re-runs the runner, exactly as for a content mismatch.
			delete(entry.changes, filePath)
			delete(entry.fileHashes, filePath)
			if len(entry.changes) == 0 {
				delete(p.cache, root)
			}
			return nil, false
		}
		// The file exists but is momentarily unreadable — a transient error. Leave
		// the entry completely intact. Return true so Remediate skips the runner
		// (which would replace this preserved entry). The LSP client will retry on
		// the next code-action request.
		p.log.Debug().Err(hashErr).Str("path", filePath).Msg("remy: transient hash error; preserving cache entry, suppressing re-run")
		return nil, true
	}
	if storedHash == "" {
		// No baseline recorded — cannot validate. Do NOT consume the entry: if we
		// evicted without being able to confirm staleness we would discard valid
		// edits. This path is unreachable with the current hashBytes implementation
		// (which always returns a non-empty hex string), but is guarded defensively.
		return nil, false
	}
	// Definitive outcome (hash computed, baseline known): consume filePath from
	// both maps. Siblings are not touched.
	edits := entry.changes[filePath]
	delete(entry.changes, filePath)
	delete(entry.fileHashes, filePath)
	if len(entry.changes) == 0 {
		delete(p.cache, root)
	}
	if curHash != storedHash {
		// Genuine content change — edits no longer apply to the current file.
		return nil, false
	}
	return edits, true
}

// Remediate returns a WorkspaceEdit limited to req.FilePath. On the first call
// for a given ContentRoot, it clones ContentRoot into an isolated git worktree,
// runs remy there, and builds a full WorkspaceEdit. Changes for req.FilePath
// are returned immediately; changes for all other files are cached for
// subsequent code action resolutions without re-running remy.
//
// Returns (nil, nil) when FindingId/ContentRoot/FilePath is empty, remy makes
// no changes to req.FilePath, or the diff produces no actionable hunks.
func (p *remyProvider) Remediate(ctx context.Context, req RemediationRequest) (*types.WorkspaceEdit, error) {
	if req.FindingId == "" || req.ContentRoot == "" || req.FilePath == "" {
		return nil, nil
	}
	root := string(req.ContentRoot)
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("remy: ContentRoot must be an absolute path, got %q", root)
	}
	// Canonicalize root so it agrees with git's canonical view (e.g. on macOS
	// os.TempDir returns /var/... but git resolves symlinks to /private/var/...).
	// Fall back to the original path on error (e.g. path does not exist yet).
	if canonical, err := filepath.EvalSymlinks(root); err == nil {
		root = canonical
	}
	filePath := string(req.FilePath)
	// Canonicalize filePath for the same reason.
	if canonical, err := filepath.EvalSymlinks(filePath); err == nil {
		filePath = canonical
	}

	if edits, ok := p.tryServeFromCache(root, filePath); ok {
		return editsToEdit(filePath, edits), nil
	}

	rootMu := p.getOrCreateRootMu(root)
	rootMu.Lock()
	defer rootMu.Unlock()

	if edits, ok := p.tryServeFromCache(root, filePath); ok {
		return editsToEdit(filePath, edits), nil
	}

	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()

	allChanges, fileHashes, err := p.runRemyInWorktree(ctx, root, req)
	if err != nil {
		return nil, err
	}
	if len(allChanges) == 0 {
		return nil, nil
	}
	p.populateCache(root, filePath, allChanges, fileHashes)

	fileEdits := allChanges[filePath]
	if len(fileEdits) == 0 {
		return nil, nil
	}
	return &types.WorkspaceEdit{Changes: map[string][]types.TextEdit{filePath: fileEdits}}, nil
}

// editsToEdit converts a slice of TextEdits into a WorkspaceEdit, returning nil
// when the slice is empty so callers get a uniform (nil, nil) no-fix signal.
func editsToEdit(filePath string, edits []types.TextEdit) *types.WorkspaceEdit {
	if len(edits) == 0 {
		return nil
	}
	return &types.WorkspaceEdit{Changes: map[string][]types.TextEdit{filePath: edits}}
}

// collectFixEdits snapshots tracked files in runDir, runs the fix workflow there,
// and builds TextEdits keyed under keyRoot. The per-finding path passes a freshly
// created worktree as runDir and the upstream repo root as keyRoot; the folder path
// passes the same already-isolated folder as both. findingID is forwarded to the
// runner so it can target a specific finding; pass "" for the folder path.
func (p *remyProvider) collectFixEdits(ctx context.Context, runDir, keyRoot, findingID string) (map[string][]types.TextEdit, map[string]string, error) {
	snapshot, err := snapshotGitFiles(ctx, runDir)
	if err != nil {
		p.log.Debug().Err(err).Str("root", runDir).Msg("remy: failed to snapshot tracked files")
		return nil, nil, fmt.Errorf("remy: snapshot: %w", err)
	}
	if err = p.runner(ctx, p.engine, runDir, findingID); err != nil {
		return nil, nil, err
	}
	return buildWorkspaceEdits(ctx, p.log, runDir, keyRoot, snapshot)
}

// runRemyInWorktree creates an isolated git worktree, runs the remy runner, and
// builds a WorkspaceEdit for all changed files. It owns the full worktree
// lifecycle (creation and cleanup via defer).
func (p *remyProvider) runRemyInWorktree(ctx context.Context, root string, req RemediationRequest) (map[string][]types.TextEdit, map[string]string, error) {
	gitRoot, err := resolveGitRoot(ctx, root)
	if err != nil {
		return nil, nil, fmt.Errorf("remy: resolve git root: %w", err)
	}
	// gitRoot is already canonical: git rev-parse --show-toplevel resolves symlinks.
	tmpParent, err := os.MkdirTemp("", "snyk-remy-*")
	if err != nil {
		return nil, nil, fmt.Errorf("remy: create temp dir: %w", err)
	}
	// Canonicalize the temp parent so the worktree path agrees with git's view.
	// On macOS os.MkdirTemp under /var/... returns a non-canonical path;
	// git worktree add resolves symlinks before recording the worktree, so the
	// path git knows differs from the path we computed — snapshot/diff lookups
	// then fail to match. EvalSymlinks after the directory is created (so the
	// path exists) gives us the same canonical form git will use.
	if canonical, evalErr := filepath.EvalSymlinks(tmpParent); evalErr == nil {
		tmpParent = canonical
	}
	worktreeDir := filepath.Join(tmpParent, "wt")
	addOut, err := exec.CommandContext(ctx, "git", "-C", gitRoot, "worktree", "add", "--detach", worktreeDir, "HEAD").CombinedOutput()
	if err != nil {
		_ = os.RemoveAll(tmpParent)
		return nil, nil, fmt.Errorf("remy: git worktree add: %w (%s)", err, addOut)
	}
	defer func() {
		// Use a fresh context with a short deadline so cleanup is bounded even
		// if the parent ctx has been canceled.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "git", "-C", gitRoot, "worktree", "remove", "--force", worktreeDir).Run()
		_ = os.RemoveAll(tmpParent)
	}()
	return p.collectFixEdits(ctx, worktreeDir, gitRoot, req.FindingId)
}

// FixFolder runs the remediation fix workflow directly in root (which must
// already be the git repository root — i.e. the top level of an isolated git
// worktree created by the caller). It does NOT create a nested worktree.
// It returns a WorkspaceEdit whose file paths are keyed under root, or
// (nil, nil) when the fix produces no changes.
//
// Precondition: root must be the git repository root (not a subdirectory).
// The daemon caller always passes a detached-HEAD worktree root, so edits are
// keyed under that root and the caller can remap paths using the passed-folder
// prefix. Passing a subdirectory is rejected with a clear error so the fix
// runner cannot silently escape its isolation boundary.
func (p *remyProvider) FixFolder(ctx context.Context, root types.FilePath) (*types.WorkspaceEdit, error) {
	r := string(root)
	if r == "" || !filepath.IsAbs(r) {
		return nil, fmt.Errorf("remy: FixFolder requires an absolute path, got %q", r)
	}
	// Guard: r must be the git repository root. git rev-parse --show-prefix
	// is symlink-safe: it outputs empty string when run at the repo root, and
	// a non-empty relative path (e.g. "sub/") when run inside a subdirectory.
	// If the command errors, the directory is not inside any git repository.
	out, err := exec.CommandContext(ctx, "git", "-C", r, "rev-parse", "--show-prefix").Output()
	if err != nil {
		return nil, fmt.Errorf("remy: FixFolder: %q is not inside a git repository: %w", r, err)
	}
	if prefix := strings.TrimSpace(string(out)); prefix != "" {
		return nil, fmt.Errorf("remy: FixFolder: %q is a subdirectory of a git repository (prefix %q); the caller must pass the git repository root", r, prefix)
	}
	// Guard: the passed worktree must be clean of tracked-file changes.
	// --untracked-files=no excludes "??" lines for untracked files (e.g. build
	// artifacts) so they do not falsely trip the guard. Only uncommitted
	// modifications to tracked files matter: they would be silently included in
	// the returned edit, making the fix unpredictable and violating the isolation
	// guarantee that the caller must pass a fresh detached-HEAD worktree.
	statusOut, err := exec.CommandContext(ctx, "git", "-C", r, "status", "--porcelain", "--untracked-files=no").Output()
	if err != nil {
		return nil, fmt.Errorf("remy: FixFolder: failed to check worktree status of %q: %w", r, err)
	}
	if status := strings.TrimSpace(string(statusOut)); status != "" {
		return nil, fmt.Errorf("remy: FixFolder: %q has uncommitted changes to tracked files; the caller must pass a clean detached-HEAD worktree:\n%s", r, status)
	}
	// findingID is "" because FixFolder targets the whole folder, not a single finding.
	// fileHashes is ignored: FixFolder returns a one-shot WorkspaceEdit and does not cache.
	changes, _, err := p.collectFixEdits(ctx, r, r, "")
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, nil
	}
	return &types.WorkspaceEdit{Changes: changes}, nil
}

// buildWorkspaceEdits enumerates files changed in the worktree relative to HEAD
// and translates each unified diff into TextEdits keyed by the real workspace path.
// Alongside the edits it returns, keyed by the SAME absolute workspace path, the
// SHA-256 of each file's pre-run HEAD content (from snapshot). That hash is the
// correct cache baseline: it is the content the edits were computed against, so
// it detects any concurrent edit made while remy was running.
func buildWorkspaceEdits(ctx context.Context, log zerolog.Logger, worktreeDir, gitRoot string, snapshot map[string][]byte) (map[string][]types.TextEdit, map[string]string, error) {
	changedPaths, err := gitChangedFiles(ctx, worktreeDir)
	if err != nil {
		return nil, nil, fmt.Errorf("remy: enumerate changed files: %w", err)
	}
	if len(changedPaths) == 0 {
		// No changes detected — log the git state so CI failures show the actual
		// worktree contents. This surfaces path-canonicalization mismatches (e.g.
		// macOS /var→/private/var symlink, Windows 8.3 short names) where the
		// snapshot keys and worktree paths diverge and git sees no diff.
		statusOut, statusErr := exec.CommandContext(ctx, "git", "-C", worktreeDir, "status", "--porcelain").Output()
		log.Debug().
			Str("worktreeDir", worktreeDir).
			Str("gitRoot", gitRoot).
			Str("gitStatus", strings.TrimSpace(string(statusOut))).
			AnErr("gitStatusErr", statusErr).
			Msg("remy: no changes detected in worktree after fix run")
		return nil, nil, nil
	}
	allChanges := make(map[string][]types.TextEdit)
	fileHashes := make(map[string]string)
	for _, relPath := range changedPaths {
		originalBytes, ok := snapshot[relPath]
		if !ok {
			continue
		}
		diff, err := gitFileDiff(ctx, worktreeDir, relPath)
		if err != nil {
			log.Debug().Err(err).Str("path", relPath).Msg("remy: failed to get diff for file")
			continue
		}
		if diff == "" {
			continue
		}
		absPath := filepath.Join(gitRoot, relPath)
		edit, err := workspaceEditFromContent(absPath, originalBytes, diff)
		if err != nil {
			log.Debug().Err(err).Str("path", relPath).Msg("remy: failed to build WorkspaceEdit for file")
			continue
		}
		if edit == nil {
			continue
		}
		for k, v := range edit.Changes {
			allChanges[k] = append(allChanges[k], v...)
			fileHashes[k] = hashBytes(originalBytes)
		}
	}
	return allChanges, fileHashes, nil
}

// normalizeLineEndings collapses CRLF pairs ("\r\n") to LF ("\n"), leaving lone
// '\r' bytes intact. Both the pre-run HEAD snapshot bytes (always LF from the
// git object store) and workspace files on Windows (CRLF when autocrlf is in
// effect) are normalized before hashing so that a pure CRLF↔LF difference does
// not cause a spurious cache miss. Lone '\r' bytes (e.g. a bare carriage return
// inside a Go string literal) are intentionally preserved: stripping them
// unconditionally would make removing a lone '\r' hash-identical to the
// baseline, masking a real content change and causing the cache to serve stale
// edits on a genuinely modified file.
func normalizeLineEndings(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// hashBytes returns the hex-encoded SHA-256 of b with line endings normalized.
// It fingerprints the pre-run HEAD content held in memory (from the snapshot).
// fileHash is its disk counterpart and applies the same normalization so that
// LF (object store) and CRLF (Windows workspace) produce equal hashes for
// equal logical content.
func hashBytes(b []byte) string {
	h := sha256.Sum256(normalizeLineEndings(b))
	return fmt.Sprintf("%x", h[:])
}

// fileHash returns the hex-encoded SHA-256 of the file at path with line
// endings normalized, or an error if the file cannot be read. Normalization
// matches hashBytes so that a workspace file written with CRLF line endings
// (Windows autocrlf) hashes equal to the LF-based snapshot baseline.
func fileHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(normalizeLineEndings(b))
	return fmt.Sprintf("%x", h[:]), nil
}

// populateCache stores changes for all files except filePath in the cache so
// that subsequent code action resolutions can be served without re-running remy.
// The baseline fingerprint for each cached file is the precomputed fileHashes
// value — the SHA-256 of the pre-run HEAD content the edits were computed
// against — NOT a post-run re-read of the workspace file. Re-reading after the
// multi-minute remy run would capture a concurrent user edit as the baseline,
// defeating staleness detection. tryServeFromCache uses these baselines to
// detect any modification independently of filesystem mtime granularity.
//
// If excluding filePath leaves the entry's changes map empty (i.e. remy only
// touched the requested file), no entry is stored. An empty entry would linger
// in the cache indefinitely: a vacuously valid entry with no files to check,
// yet there is nothing to serve and the evict-when-empty path in tryServeFromCache
// is never reached.
func (p *remyProvider) populateCache(root, filePath string, allChanges map[string][]types.TextEdit, fileHashes map[string]string) {
	entry := &remyCacheEntry{
		changes:    make(map[string][]types.TextEdit, len(allChanges)-1),
		fileHashes: make(map[string]string, len(allChanges)-1),
	}
	for k, v := range allChanges {
		if k != filePath {
			entry.changes[k] = v
			entry.fileHashes[k] = fileHashes[k]
		}
	}
	if len(entry.changes) == 0 {
		// Nothing to cache — storing an empty entry would create a ghost that is
		// vacuously valid but can never be served.
		return
	}
	p.cacheMu.Lock()
	p.cache[root] = entry
	p.cacheMu.Unlock()
}

// InvalidateFile removes cached diffs for path from every cache entry so that
// the next Remediate call for that file re-runs remy rather than serving stale
// results. It is called by the LSP textDocument/didChange handler. The
// corresponding fileHashes entry is deleted alongside the changes entry so
// both maps stay in sync.
//
// The path is canonicalized via filepath.EvalSymlinks (with fallback on error)
// before the cache lookup so that it matches the canonical key inserted by
// Remediate. Without canonicalization, a non-canonical path (e.g. a symlinked
// path on macOS /var→/private/var) would miss the canonical cache key and leave
// stale entries alive.
func (p *remyProvider) InvalidateFile(path types.FilePath) {
	s := string(path)
	if canonical, err := filepath.EvalSymlinks(s); err == nil {
		s = canonical
	} else if dir, derr := filepath.EvalSymlinks(filepath.Dir(s)); derr == nil {
		// The file itself no longer exists (e.g. a fix deleted it and then
		// didChange/didClose fired). EvalSymlinks on the file fails, but the
		// parent directory still exists and can be resolved. Rejoin the base
		// name to produce the same canonical path that Remediate wrote into
		// the cache (Remediate calls EvalSymlinks while the file still existed).
		//
		// Limitation: if the missing file's basename was itself a symlink (rare),
		// the reconstructed key may not match the canonical key stored by Remediate,
		// in which case the delete is a harmless no-op — the stale entry simply is
		// not evicted, the same outcome as before symlink canonicalization was added.
		s = filepath.Join(dir, filepath.Base(s))
	}
	canonPath := s
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	for root, entry := range p.cache {
		delete(entry.changes, canonPath)
		delete(entry.fileHashes, canonPath)
		// Remove the cache entry entirely once it has no remaining changes so
		// it does not occupy memory or cause vacuously-valid hits.
		if len(entry.changes) == 0 {
			delete(p.cache, root)
		}
	}
}

// resolveGitRoot returns the root of the git repository containing path by
// running git rev-parse --show-toplevel. This is necessary when path is a
// subdirectory of a git repo (e.g. a monorepo package folder) so that worktree
// paths and diff paths are all relative to the same root.
func resolveGitRoot(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// snapshotGitFiles returns a map of relative path → original bytes for every
// file currently tracked in the git repository at root.
func snapshotGitFiles(ctx context.Context, root string) (map[string][]byte, error) {
	// List all tracked files via git ls-files so we know which ones were
	// present before remy runs.
	cmd := exec.CommandContext(ctx, "git", "-C", root, "ls-files")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}

	snapshot := make(map[string][]byte)
	for _, relPath := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if relPath == "" {
			continue
		}
		content, err := gitShowHEAD(ctx, root, relPath)
		if err != nil {
			continue
		}
		snapshot[relPath] = content
	}
	return snapshot, nil
}

// gitShowHEAD returns the content of relPath at HEAD in the repo at root.
func gitShowHEAD(ctx context.Context, root, relPath string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", root, "show", "HEAD:"+relPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git show HEAD:%s: %w (%s)", relPath, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// gitChangedFiles returns the relative paths of files that differ from HEAD in
// the working tree at root.
func gitChangedFiles(ctx context.Context, root string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", root, "diff", "--name-only", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only: %w", err)
	}
	var paths []string
	for _, p := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// gitFileDiff returns the unified diff for relPath from HEAD to the working
// tree in the repository at root. Returns an empty string if the file is
// unchanged.
func gitFileDiff(ctx context.Context, root, relPath string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", root, "diff", "HEAD", "--", relPath)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git diff HEAD -- %s: %w", relPath, err)
	}
	return string(out), nil
}

// workspaceEditFromContent converts a unified diff into a WorkspaceEdit keyed
// by absPath. originalContent is used as the source of truth for line counts
// (the file at absPath may already contain the new content after the runner ran).
func workspaceEditFromContent(absPath string, originalContent []byte, diff string) (*types.WorkspaceEdit, error) {
	if len(originalContent) == 0 {
		return nil, fmt.Errorf("original content for %s is empty", absPath)
	}

	originalLines := strings.Split(string(originalContent), "\n")
	lastLine := len(originalLines)

	diffLines := strings.Split(diff, "\n")
	// Remove trailing empty line from the split if present.
	if n := len(diffLines); n > 0 && diffLines[n-1] == "" {
		diffLines = diffLines[:n-1]
	}
	if len(diffLines) == 0 {
		return nil, fmt.Errorf("diff is empty")
	}

	textEdits, err := parseDiffHunks(diffLines, lastLine)
	if err != nil {
		return nil, err
	}
	if len(textEdits) == 0 {
		return nil, nil
	}

	return &types.WorkspaceEdit{
		Changes: map[string][]types.TextEdit{
			absPath: textEdits,
		},
	}, nil
}

// hunkHeader matches a unified diff @@ hunk header.
var hunkHeader = regexp.MustCompile(`@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@`)

// diffState holds the mutable state threaded through parseDiffHunks.
type diffState struct {
	currentLine      int
	textEdits        []types.TextEdit
	lastWasInsertion bool // true iff the immediately preceding diff content line was '+'
}

// applyDeletion records a deletion TextEdit and advances the original-file cursor.
func applyDeletion(s *diffState, lastLine int) error {
	te, err := makeLineEdit(s.currentLine, s.currentLine+1, "", lastLine)
	if err != nil {
		return err
	}
	s.textEdits = append(s.textEdits, *te)
	s.currentLine++ // the deleted line still existed in the original
	s.lastWasInsertion = false
	return nil
}

// applyInsertion records an insertion TextEdit, merging consecutive insertions
// at the same source line into a single edit for atomic LSP application.
func applyInsertion(s *diffState, line string, lastLine int) error {
	newText := strings.TrimPrefix(line, "+") + "\n"
	if len(s.textEdits) > 0 &&
		s.textEdits[len(s.textEdits)-1].NewText != "" &&
		s.textEdits[len(s.textEdits)-1].Range.Start.Line == s.currentLine {
		s.textEdits[len(s.textEdits)-1].NewText += newText
		s.lastWasInsertion = true
		return nil
	}
	te, err := makeLineEdit(s.currentLine, s.currentLine, newText, lastLine)
	if err != nil {
		return err
	}
	s.textEdits = append(s.textEdits, *te)
	// Insertions do not advance the original-file cursor.
	s.lastWasInsertion = true
	return nil
}

// parseDiffHunks translates unified diff lines (the @@ … blocks) into LSP
// TextEdits against the original file (lastLine is the total number of lines
// in the original). It follows the same logic as infrastructure/code/convert.go
// processLines so that edits are compatible with how the rest of the language
// server applies fixes.
func parseDiffHunks(diffLines []string, lastLine int) ([]types.TextEdit, error) {
	s := &diffState{}
	// inHunk tracks whether we have seen at least one @@ header. Before the
	// first hunk, all lines are file/extended headers and must be skipped.
	// After the first @@, lines starting with "-" or "+" are content, not
	// headers — checking "---"/"+++" before "-"/"+" would silently drop
	// deletions of lines beginning with "--" and insertions of "++" lines.
	inHunk := false

	for _, line := range diffLines {
		if strings.HasPrefix(line, "@@") {
			inHunk = true
			m := hunkHeader.FindStringSubmatch(line)
			if m == nil {
				return nil, fmt.Errorf("malformed hunk header: %s", line)
			}
			n, _ := strconv.Atoi(m[1])
			s.currentLine = n - 1 // convert to 0-indexed
			s.lastWasInsertion = false
			continue
		}
		if !inHunk {
			// Pre-hunk lines: "--- a/file", "+++ b/file", "diff --git", "index", etc.
			continue
		}
		if strings.HasPrefix(line, "-") {
			if err := applyDeletion(s, lastLine); err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(line, "+") {
			if err := applyInsertion(s, line, lastLine); err != nil {
				return nil, err
			}
			continue
		}
		if line == `\ No newline at end of file` {
			if s.lastWasInsertion {
				// The immediately preceding diff line was a '+' insertion.
				// applyInsertion always appends "\n"; strip it since the
				// inserted content does not end with a newline.
				last := len(s.textEdits) - 1
				s.textEdits[last].NewText = strings.TrimSuffix(s.textEdits[last].NewText, "\n")
			} else {
				// The immediately preceding diff line was a '-' deletion;
				// applyDeletion advanced the cursor, so compensate.
				s.currentLine--
			}
			s.lastWasInsertion = false
			continue
		}
		if strings.HasPrefix(line, " ") {
			// Context line: advance the original-file cursor.
			s.currentLine++
			s.lastWasInsertion = false
			continue
		}
		// Any other in-hunk line is silently skipped.
	}
	return s.textEdits, nil
}

// makeLineEdit constructs a single-line TextEdit. startLine and endLine are
// 0-indexed; lastLine is the total number of lines in the original file.
func makeLineEdit(startLine, endLine int, newText string, lastLine int) (*types.TextEdit, error) {
	if startLine < 0 || endLine < 0 {
		return nil, fmt.Errorf(
			"cannot create TextEdit where start (%d) or end (%d) is negative",
			startLine, endLine,
		)
	}
	if startLine > lastLine || endLine > lastLine {
		return nil, fmt.Errorf(
			"cannot create TextEdit where start (%d) or end (%d) exceeds file length (%d)",
			startLine, endLine, lastLine,
		)
	}
	return &types.TextEdit{
		Range: types.Range{
			Start: types.Position{Line: startLine, Character: 0},
			End:   types.Position{Line: endLine, Character: 0},
		},
		NewText: newText,
	}, nil
}
