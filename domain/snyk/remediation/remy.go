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
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

type remyProvider struct {
	opts   RemyOptions
	runner remyRunner
	engine workflow.Engine
	log    zerolog.Logger
}

// Ensure remyProvider satisfies the FolderRemediator interface at compile time.
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
func NewRemyProvider(engine workflow.Engine, runner remyRunner) *remyProvider {
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
	return &remyProvider{opts: opts, runner: runner, engine: engine, log: log}
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
	// Bound the folder-wide run with the configured timeout so a hung fix
	// cannot stall the caller indefinitely.
	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
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
	inHunk := false

	for _, line := range diffLines {
		if !inHunk && (strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++")) {
			// File header lines appear before the first @@ hunk; skip them.
			// Inside a hunk, "---" is a deletion of a "--"-prefixed line and
			// "+++" is an insertion of a "++" line — handled by the +/- branches.
			continue
		}
		if strings.HasPrefix(line, "@@") {
			m := hunkHeader.FindStringSubmatch(line)
			if m == nil {
				return nil, fmt.Errorf("malformed hunk header: %s", line)
			}
			n, _ := strconv.Atoi(m[1])
			s.currentLine = n - 1 // convert to 0-indexed
			s.lastWasInsertion = false
			inHunk = true
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
		// All remaining lines (git extended headers like "diff --git …",
		// "index …", and any other unrecognized lines) are silently skipped.
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
