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
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/internal/types"
)

// remyRunner is the seam that lets tests inject a fake runner without shelling
// out to a real CLI. The real implementation executes the host snyk binary with
// the remy subcommand.
//
// root is the absolute path of the git worktree to operate on.
// findingID is the stable identifier of the finding to fix.
type remyRunner func(ctx context.Context, root string, findingID string) error

// RemyOptions controls the behavior of the concrete remy-backed provider.
type RemyOptions struct {
	// CliPath is the absolute path of the host snyk binary. Required when
	// using the default subprocess runner.
	CliPath string

	// Timeout caps how long a single remediation attempt may run. When zero,
	// a 5-minute default applies.
	Timeout time.Duration

	// Logger receives structured operational logs. When nil, a discarding
	// logger is used so the dependency stays optional for callers that do
	// not need logging.
	Logger *zerolog.Logger
}

// remyProvider is the concrete RemediationProvider that drives the host snyk
// binary's remy subcommand to apply an LLM-generated fix and translates the
// resulting file changes into a WorkspaceEdit.
type remyProvider struct {
	opts   RemyOptions
	runner remyRunner
	log    zerolog.Logger
}

// Ensure remyProvider satisfies the interface at compile time.
var _ RemediationProvider = (*remyProvider)(nil)

// NewRemyProvider constructs a remyProvider.
//
// runner is the test seam; pass nil to use the default subprocess runner which
// shells out to opts.CliPath. Callers that want to plug in a fake runner for
// unit tests pass a non-nil function here.
func NewRemyProvider(opts RemyOptions, runner remyRunner) RemediationProvider {
	log := zerolog.Nop()
	if opts.Logger != nil {
		log = *opts.Logger
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}
	if runner == nil {
		runner = makeSubprocessRunner(opts, log)
	}
	return &remyProvider{opts: opts, runner: runner, log: log}
}

// Remediate runs remy against req.ContentRoot (a git worktree supplied by the
// caller), lets remy mutate it in place, then builds a WorkspaceEdit from the
// before/after diff of every changed file.
//
// The provider never copies, restores, or verifies the worktree. Isolation and
// post-fix verification are the caller's responsibility.
//
// Returns (nil, nil) when:
//   - FindingId or ContentRoot is empty
//   - remy makes no changes
//   - the diff produces no actionable hunks
func (p *remyProvider) Remediate(ctx context.Context, req RemediationRequest) (*types.WorkspaceEdit, error) {
	// Guard: both fields must be present before doing any real work.
	if req.FindingId == "" || req.ContentRoot == "" {
		return nil, nil
	}

	root := string(req.ContentRoot)
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("remy: ContentRoot must be an absolute path, got %q", root)
	}

	// Apply a timeout to the subprocess so a hung LLM call does not block
	// the language-server indefinitely.
	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()

	// Snapshot the pre-mutation state of every tracked file so we can
	// recover the original content after remy writes its changes.
	snapshot, err := snapshotGitFiles(ctx, root)
	if err != nil {
		p.log.Debug().Err(err).Str("root", root).Msg("remy: failed to snapshot tracked files")
		return nil, fmt.Errorf("remy: snapshot: %w", err)
	}

	// Run remy via the injected runner. The runner mutates ContentRoot in
	// place — that is the intended outcome.
	err = p.runner(ctx, root, req.FindingId)
	if err != nil {
		return nil, err
	}

	// Enumerate files that changed after the runner finished.
	changedPaths, err := gitChangedFiles(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("remy: enumerate changed files: %w", err)
	}
	if len(changedPaths) == 0 {
		return nil, nil
	}

	// Build a merged WorkspaceEdit from all changed files.
	merged := &types.WorkspaceEdit{Changes: make(map[string][]types.TextEdit)}
	for _, relPath := range changedPaths {
		absPath := filepath.Join(root, relPath)

		originalBytes, ok := snapshot[relPath]
		if !ok {
			// File was untracked before remy — skip: we only diff tracked files.
			continue
		}

		diff, err := gitFileDiff(ctx, root, relPath)
		if err != nil {
			p.log.Debug().Err(err).Str("path", relPath).Msg("remy: failed to get diff for file")
			continue
		}
		if diff == "" {
			continue
		}

		edit, err := workspaceEditFromContent(absPath, originalBytes, diff)
		if err != nil {
			p.log.Debug().Err(err).Str("path", relPath).Msg("remy: failed to build WorkspaceEdit for file")
			continue
		}
		for k, v := range edit.Changes {
			merged.Changes[k] = append(merged.Changes[k], v...)
		}
	}

	if len(merged.Changes) == 0 {
		return nil, nil
	}
	return merged, nil
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
		// Read from HEAD so we always capture the committed content
		// regardless of any in-progress changes.
		content, err := gitShowHEAD(ctx, root, relPath)
		if err != nil {
			// File may be staged but not committed yet; read from disk as
			// a best-effort fallback.
			content, err = os.ReadFile(filepath.Join(root, relPath))
			if err != nil {
				continue
			}
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

	for _, line := range diffLines {
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
			// Ignore unified diff file header lines.
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

// makeSubprocessRunner returns the default remyRunner that shells out to the
// host snyk binary's remy subcommand.
//
// findingID is passed as a parameter for correlation (matching remy's output
// back to the triggering finding) but is not forwarded to the CLI args because
// the remy subcommand operates on the entire ContentRoot — it scans the project
// and attempts to fix all findings it discovers rather than targeting a specific
// one. The findingID is therefore used only for logging and response mapping by
// the caller.
//
// TODO: thread a configResolver through RemyOptions so that
// AppendCliEnvironmentVariables can be used here instead of os.Environ().
// Until then we inherit the parent process environment as-is.
func makeSubprocessRunner(opts RemyOptions, log zerolog.Logger) remyRunner {
	return func(ctx context.Context, root string, findingID string) error {
		if opts.CliPath == "" {
			log.Debug().Msg("remy: no CLI path configured; skipping subprocess")
			return nil
		}

		// Pass --experimental and --beast-mode so remy runs non-interactively:
		// --experimental is required by the remy workflow guard, and
		// --beast-mode auto-approves all proposed fixes without prompting.
		args := []string{"remy", root, "--experimental", "--beast-mode"}

		cmd := exec.CommandContext(ctx, opts.CliPath, args...)
		cmd.Stdin = nil // closed stdin so remy never blocks on a prompt
		cmd.Env = os.Environ()

		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf

		log.Debug().
			Str("cli", opts.CliPath).
			Str("root", root).
			Str("finding_id", findingID).
			Msg("remy: starting subprocess")

		if err := cmd.Run(); err != nil {
			log.Debug().
				Err(err).
				Str("stdout", outBuf.String()).
				Str("stderr", errBuf.String()).
				Msg("remy: subprocess exited with error")
			return fmt.Errorf("remy subprocess: %w", err)
		}

		log.Debug().
			Str("stdout", outBuf.String()).
			Msg("remy: subprocess completed successfully")
		return nil
	}
}
