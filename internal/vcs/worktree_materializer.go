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

// This file writes base branch worktrees itself instead of using go-git's
// checkout, which refuses Windows reserved device names such as prn.sh on every
// OS. Setting core.protectNTFS=false would fix macOS and Linux but not Windows,
// where the OS intercepts the name and only an extended-length path gets past
// it, and it would drop go-git's .git-disguise mitigations wholesale. The
// validators go-git applies at that layer are reproduced below.

package vcs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/rs/zerolog"
)

const (
	gitmodulesFile = ".gitmodules"
	// maxTreeDepth matches go-git's own limit on self-referencing trees.
	maxTreeDepth = 1024
)

var (
	// ErrInvalidTreeEntryName is returned for a tree entry name that git itself
	// could not have produced.
	ErrInvalidTreeEntryName = errors.New("invalid tree entry name")
	// ErrRejectedTreeEntryPath is returned when go-git's own tree path validation
	// rejects an entry, which is what guards ".." and the .git disguises.
	ErrRejectedTreeEntryPath = errors.New("tree entry path rejected")
	// ErrUnsupportedTreeEntryMode is returned for a tree entry whose mode is not
	// one this package knows how to materialize.
	ErrUnsupportedTreeEntryMode = errors.New("unsupported tree entry mode")
	// ErrGitModulesSymlink mirrors go-git's refusal to check out a symlinked
	// .gitmodules, which is upstream git's CVE-2018-11235 mitigation.
	ErrGitModulesSymlink = errors.New(gitmodulesFile + " is a symlink")
	// ErrMaxTreeDepth is returned for a tree nested past maxTreeDepth.
	ErrMaxTreeDepth = errors.New("maximum tree depth exceeded")
	// ErrRelativeWorktreeRoot is returned when the destination is not absolute,
	// which on Windows would silently disable extended-length path handling.
	ErrRelativeWorktreeRoot = errors.New("worktree root must be an absolute path")
)

// pendingSymlink is a symlink held back until every directory and regular file
// has been written.
type pendingSymlink struct {
	path string
	hash plumbing.Hash
}

// worktreeWriter materializes one commit's tree into rootPath.
type worktreeWriter struct {
	logger          *zerolog.Logger
	repo            *git.Repository
	rootPath        string
	pendingSymlinks []pendingSymlink
}

// materializeWorktree writes commitHash's tree to rootPath, which must be an
// empty absolute directory: the writes below rely on nothing already being
// there. Entries this platform cannot represent (submodules, and names holding
// a separator) are logged and skipped; anything else is written or fails.
func materializeWorktree(logger *zerolog.Logger, repo *git.Repository, rootPath string, commitHash plumbing.Hash) error {
	if !filepath.IsAbs(rootPath) {
		return fmt.Errorf("%w: %q", ErrRelativeWorktreeRoot, rootPath)
	}

	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		return err
	}
	tree, err := commit.Tree()
	if err != nil {
		return err
	}

	writer := &worktreeWriter{logger: logger, repo: repo, rootPath: rootPath}
	if err = writer.writeTree(tree, "", 0); err != nil {
		return err
	}

	// Symlinks are written last so one can never be a leading component of a
	// path still to be written, which the directory and file writes would follow.
	for _, symlink := range writer.pendingSymlinks {
		if err = writer.writeSymlink(symlink); err != nil {
			return err
		}
	}
	return nil
}

// writeTree walks tree itself rather than using object.NewTreeWalker, whose
// documented behavior is to skip objects it cannot load - it turns a failed
// subtree read into io.EOF, which would end the walk and report a partial
// worktree as a complete one.
func (w *worktreeWriter) writeTree(tree *object.Tree, prefix string, depth int) error {
	if depth > maxTreeDepth {
		return fmt.Errorf("%w at %q", ErrMaxTreeDepth, prefix)
	}

	for _, entry := range tree.Entries {
		if err := checkTreeEntryName(tree, entry); err != nil {
			return err
		}
		name := path.Join(prefix, entry.Name)

		// A backslash is an ordinary character in a POSIX file name and real
		// repositories hold such files, but on Windows it is a path separator.
		if runtime.GOOS == "windows" && strings.ContainsRune(entry.Name, '\\') {
			w.logger.Warn().Str("path", name).Msg("base branch worktree omits an entry whose name this platform cannot represent")
			continue
		}

		if err := w.writeEntry(entry, name, depth); err != nil {
			return err
		}
	}
	return nil
}

func (w *worktreeWriter) writeEntry(entry object.TreeEntry, name string, depth int) error {
	target := filepath.Join(w.rootPath, filepath.FromSlash(name))

	switch entry.Mode {
	case filemode.Dir:
		subtree, err := object.GetTree(w.repo.Storer, entry.Hash)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(OSPath(target), 0700); err != nil {
			return err
		}
		return w.writeTree(subtree, name, depth+1)
	case filemode.Symlink:
		if err := rejectGitmodulesSymlink(name); err != nil {
			return err
		}
		w.pendingSymlinks = append(w.pendingSymlinks, pendingSymlink{path: target, hash: entry.Hash})
		return nil
	case filemode.Regular, filemode.Deprecated, filemode.Executable:
		return w.writeFile(target, name, entry)
	case filemode.Submodule:
		// Nothing to check out, and we never run submodule update on this clone.
		w.logger.Warn().Str("path", name).Msg("base branch worktree omits a submodule")
		return nil
	default:
		return fmt.Errorf("%w: %q is %v", ErrUnsupportedTreeEntryMode, name, entry.Mode)
	}
}

func (w *worktreeWriter) writeFile(target, name string, entry object.TreeEntry) error {
	err := writeWorktreeFile(w.repo, target, entry.Hash, entry.Mode)
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return err
	}
	// Two entries differing only in case or Unicode form, on a filesystem that
	// folds them together: the first written wins, as under go-git's checkout.
	w.logger.Warn().Str("path", name).Msg("base branch worktree omits an entry whose path another entry already took")
	return nil
}

// checkTreeEntryName applies the two name guards: git stores exactly one path
// component per entry, so a slash cannot come from an object git produced and is
// the only way a deferred symlink could parent a later write; and go-git's
// ValidTreePath rejects "..", ".git" and its HFS+ and NTFS disguises at every
// position, independently of any config.
func checkTreeEntryName(tree *object.Tree, entry object.TreeEntry) error {
	if strings.ContainsRune(entry.Name, '/') {
		return fmt.Errorf("%w: %q", ErrInvalidTreeEntryName, entry.Name)
	}
	if _, err := tree.FindEntry(entry.Name); err != nil {
		return fmt.Errorf("%w: %q: %w", ErrRejectedTreeEntryPath, entry.Name, err)
	}
	return nil
}

// rejectGitmodulesSymlink reproduces go-git's validSymlinkName, which refuses a
// symlink whose path names .gitmodules so a checkout cannot plant submodule
// config. The NTFS and HFS+ disguises it also covers need go-git internals we
// cannot import, so only the plain name is matched here.
func rejectGitmodulesSymlink(name string) error {
	for _, part := range strings.Split(name, "/") {
		if strings.EqualFold(part, gitmodulesFile) {
			return fmt.Errorf("%w: %q", ErrGitModulesSymlink, name)
		}
	}
	return nil
}

func writeWorktreeFile(repo *git.Repository, target string, hash plumbing.Hash, mode filemode.FileMode) error {
	blob, err := repo.BlobObject(hash)
	if err != nil {
		return err
	}
	reader, err := blob.Reader()
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	perm := os.FileMode(0600)
	if mode == filemode.Executable {
		perm = 0700
	}
	file, err := createWorktreeFile(target, perm)
	if err != nil {
		return err
	}

	if _, err = io.Copy(file, reader); err != nil {
		_ = file.Close()
		return err
	}
	// Not deferred: a Close error means the bytes never landed, and a truncated
	// blob would otherwise be persisted as part of the baseline.
	return file.Close()
}

// createWorktreeFile opens target for writing. O_EXCL because the root starts
// empty, so an existing path means two tree entries collided and the caller
// gets to decide rather than one silently overwriting the other.
func createWorktreeFile(target string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(OSPath(target), os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
}

func (w *worktreeWriter) writeSymlink(symlink pendingSymlink) error {
	return writeWorktreeSymlink(w.logger, w.repo, symlink.path, symlink.hash)
}

func writeWorktreeSymlink(logger *zerolog.Logger, repo *git.Repository, target string, hash plumbing.Hash) error {
	blob, err := repo.BlobObject(hash)
	if err != nil {
		return err
	}
	reader, err := blob.Reader()
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	linkTarget, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// Parent directories already exist from the first pass.
	switch err = os.Symlink(string(linkTarget), OSPath(target)); {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrExist):
		logger.Warn().Err(err).Str("path", target).Msg("base branch worktree omits a symlink whose path another entry already took")
		return nil
	case isSymlinkPrivilegeError(err):
		// What git does under core.symlinks=false: store the link text as a file,
		// so the scan sees the entry instead of a hole in the baseline.
		return writeWorktreeSymlinkFallback(logger, target, linkTarget)
	default:
		return err
	}
}

func writeWorktreeSymlinkFallback(logger *zerolog.Logger, target string, linkTarget []byte) error {
	file, err := createWorktreeFile(target, 0600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			logger.Warn().Err(err).Str("path", target).Msg("base branch worktree omits a symlink whose path another entry already took")
			return nil
		}
		return err
	}
	if _, err = file.Write(linkTarget); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
