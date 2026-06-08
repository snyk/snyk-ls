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
	"fmt"
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
// path. createdAt is used for mtime-based eviction.
type remyCacheEntry struct {
	changes   map[string][]types.TextEdit
	createdAt time.Time
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

// Ensure remyProvider satisfies both interfaces at compile time.
var _ RemediationProvider = (*remyProvider)(nil)
var _ FileChangeNotifier = (*remyProvider)(nil)

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

// tryServeFromCache looks up the cache for root/filePath. Holds cacheMu for
// the full read-validate-consume cycle so that cacheValid (which iterates
// entry.changes) and InvalidateFile (which deletes from entry.changes) are
// never concurrent — preventing a data race on the shared map.
// Returns (edits, true) on a valid cache hit, (nil, false) otherwise.
func (p *remyProvider) tryServeFromCache(root, filePath string) ([]types.TextEdit, bool) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	entry, exists := p.cache[root]
	if !exists || !p.cacheValid(entry) {
		return nil, false
	}
	edits, ok := entry.changes[filePath]
	if !ok {
		return nil, false
	}
	delete(entry.changes, filePath)
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
	filePath := string(req.FilePath)

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

	allChanges, err := p.runRemyInWorktree(ctx, root, req)
	if err != nil {
		return nil, err
	}
	if len(allChanges) == 0 {
		return nil, nil
	}
	p.populateCache(root, filePath, allChanges)

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

// runRemyInWorktree creates an isolated git worktree, runs the remy runner, and
// builds a WorkspaceEdit for all changed files. It owns the full worktree
// lifecycle (creation and cleanup via defer).
func (p *remyProvider) runRemyInWorktree(ctx context.Context, root string, req RemediationRequest) (map[string][]types.TextEdit, error) {
	gitRoot, err := resolveGitRoot(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("remy: resolve git root: %w", err)
	}
	tmpParent, err := os.MkdirTemp("", "snyk-remy-*")
	if err != nil {
		return nil, fmt.Errorf("remy: create temp dir: %w", err)
	}
	worktreeDir := filepath.Join(tmpParent, "wt")
	addOut, err := exec.CommandContext(ctx, "git", "-C", gitRoot, "worktree", "add", "--detach", worktreeDir, "HEAD").CombinedOutput()
	if err != nil {
		_ = os.RemoveAll(tmpParent)
		return nil, fmt.Errorf("remy: git worktree add: %w (%s)", err, addOut)
	}
	defer func() {
		// Use a fresh context with a short deadline so cleanup is bounded even
		// if the parent ctx has been canceled.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "git", "-C", gitRoot, "worktree", "remove", "--force", worktreeDir).Run()
		_ = os.RemoveAll(tmpParent)
	}()
	snapshot, err := snapshotGitFiles(ctx, worktreeDir)
	if err != nil {
		p.log.Debug().Err(err).Str("root", worktreeDir).Msg("remy: failed to snapshot tracked files")
		return nil, fmt.Errorf("remy: snapshot: %w", err)
	}
	if err = p.runner(ctx, p.engine, worktreeDir, req.FindingId); err != nil {
		return nil, err
	}
	return buildWorkspaceEdits(ctx, p.log, worktreeDir, gitRoot, snapshot)
}

// buildWorkspaceEdits enumerates files changed in the worktree relative to HEAD
// and translates each unified diff into TextEdits keyed by the real workspace path.
func buildWorkspaceEdits(ctx context.Context, log zerolog.Logger, worktreeDir, gitRoot string, snapshot map[string][]byte) (map[string][]types.TextEdit, error) {
	changedPaths, err := gitChangedFiles(ctx, worktreeDir)
	if err != nil {
		return nil, fmt.Errorf("remy: enumerate changed files: %w", err)
	}
	if len(changedPaths) == 0 {
		return nil, nil
	}
	allChanges := make(map[string][]types.TextEdit)
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
		edit, err := workspaceEditFromContent(filepath.Join(gitRoot, relPath), originalBytes, diff)
		if err != nil {
			log.Debug().Err(err).Str("path", relPath).Msg("remy: failed to build WorkspaceEdit for file")
			continue
		}
		if edit == nil {
			continue
		}
		for k, v := range edit.Changes {
			allChanges[k] = append(allChanges[k], v...)
		}
	}
	return allChanges, nil
}

// populateCache stores changes for all files except filePath in the cache so
// that subsequent code action resolutions can be served without re-running remy.
func (p *remyProvider) populateCache(root, filePath string, allChanges map[string][]types.TextEdit) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	entry := &remyCacheEntry{
		changes:   make(map[string][]types.TextEdit, len(allChanges)-1),
		createdAt: time.Now(),
	}
	for k, v := range allChanges {
		if k != filePath {
			entry.changes[k] = v
		}
	}
	p.cache[root] = entry
}

// InvalidateFile removes cached diffs for path from every cache entry so that
// the next Remediate call for that file re-runs remy rather than serving stale
// results. It is called by the LSP textDocument/didChange handler.
func (p *remyProvider) InvalidateFile(path types.FilePath) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	for root, entry := range p.cache {
		delete(entry.changes, string(path))
		// Remove the cache entry entirely once it has no remaining changes so
		// it does not occupy memory or cause vacuously-valid hits.
		if len(entry.changes) == 0 {
			delete(p.cache, root)
		}
	}
}

// cacheValid returns false if any file in the entry has been modified on disk
// since the entry was created, indicating the cached diffs are stale.
func (p *remyProvider) cacheValid(entry *remyCacheEntry) bool {
	for path := range entry.changes {
		info, err := os.Stat(path)
		if err != nil || info.ModTime().After(entry.createdAt) {
			return false
		}
	}
	return true
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
