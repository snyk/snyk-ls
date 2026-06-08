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
	"context"
	"fmt"
	"os/exec"
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

// remyProvider is the concrete implementation that drives the remy workflow.
type remyProvider struct {
	opts   RemyOptions
	runner remyRunner
	engine workflow.Engine
	log    zerolog.Logger
}

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
