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

package testutil

import (
	"io"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

// GitFixtureFile is one committed file: Content is the blob payload, or the
// link target when Mode is filemode.Symlink.
type GitFixtureFile struct {
	Content string
	Mode    filemode.FileMode
}

// InitGitRepo creates an empty repository at repoPath carrying an origin remote.
func InitGitRepo(t *testing.T, repoPath types.FilePath) *git.Repository {
	t.Helper()
	repo, err := git.PlainInit(string(repoPath), false)
	require.NoError(t, err)

	repoConfig, err := repo.Config()
	require.NoError(t, err)
	repoConfig.Remotes["origin"] = &config.RemoteConfig{
		Name: "origin",
		URLs: []string{"git@github.com:snyk/snyk-goof.git"},
	}
	require.NoError(t, repo.Storer.SetConfig(repoConfig))
	return repo
}

// InitGitRepoWithFiles creates a repository at repoPath whose master branch
// holds files, keyed by slash-separated relative path.
func InitGitRepoWithFiles(t *testing.T, repoPath types.FilePath, files map[string]string) *git.Repository {
	t.Helper()
	entries := make(map[string]GitFixtureFile, len(files))
	for name, content := range files {
		entries[name] = GitFixtureFile{Content: content, Mode: filemode.Regular}
	}
	return InitGitRepoWithEntries(t, repoPath, entries)
}

// InitGitRepoWithEntries is InitGitRepoWithFiles with per-file modes. It writes
// objects only and leaves the worktree empty, so a fixture can commit names the
// host filesystem would refuse to create. Tests that need the files on disk as
// well must write them themselves.
func InitGitRepoWithEntries(t *testing.T, repoPath types.FilePath, files map[string]GitFixtureFile) *git.Repository {
	t.Helper()
	repo := InitGitRepo(t, repoPath)

	root := &gitTreeNode{}
	for name, file := range files {
		root.add(t, repo.Storer, strings.Split(name, "/"), file)
	}
	CommitGitTree(t, repo, root.write(t, repo.Storer))
	return repo
}

// WriteGitBlob stores content as a blob object and returns its hash.
func WriteGitBlob(t *testing.T, storer storage.Storer, content string) plumbing.Hash {
	t.Helper()
	blob := storer.NewEncodedObject()
	blob.SetType(plumbing.BlobObject)
	writer, err := blob.Writer()
	require.NoError(t, err)
	_, err = io.WriteString(writer, content)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return storeGitObject(t, storer, blob)
}

// WriteGitTree stores entries as a tree object and returns its hash. Entries are
// sorted into git's canonical order, so callers may pass them in any order.
func WriteGitTree(t *testing.T, storer storage.Storer, entries []object.TreeEntry) plumbing.Hash {
	t.Helper()
	sorted := slices.Clone(entries)
	sort.Sort(object.TreeEntrySorter(sorted))

	treeObject := storer.NewEncodedObject()
	require.NoError(t, (&object.Tree{Entries: sorted}).Encode(treeObject))
	return storeGitObject(t, storer, treeObject)
}

// CommitGitTree commits treeHash as master's tip and points HEAD at master.
func CommitGitTree(t *testing.T, repo *git.Repository, treeHash plumbing.Hash) plumbing.Hash {
	t.Helper()
	return CommitGitTreeOnBranch(t, repo, plumbing.Master, treeHash)
}

// CommitGitTreeOnBranch commits treeHash as branchName's tip with the given
// parents and points HEAD at branchName.
func CommitGitTreeOnBranch(
	t *testing.T,
	repo *git.Repository,
	branchName plumbing.ReferenceName,
	treeHash plumbing.Hash,
	parents ...plumbing.Hash,
) plumbing.Hash {
	t.Helper()
	signature := object.Signature{Name: t.Name(), Email: "test@example.com", When: time.Unix(0, 0).UTC()}
	commitObject := repo.Storer.NewEncodedObject()
	require.NoError(t, (&object.Commit{
		Author:       signature,
		Committer:    signature,
		Message:      "init",
		TreeHash:     treeHash,
		ParentHashes: parents,
	}).Encode(commitObject))
	commitHash := storeGitObject(t, repo.Storer, commitObject)

	require.NoError(t, repo.Storer.SetReference(plumbing.NewHashReference(branchName, commitHash)))
	require.NoError(t, repo.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, branchName)))
	return commitHash
}

// DetachGitRepoHeadBehindMaster advances master by one commit and leaves HEAD
// on the previous one. A shallow clone of master cannot be served from that
// state, which is what makes vcs.Clone fall back to copying the .git directory.
func DetachGitRepoHeadBehindMaster(t *testing.T, repo *git.Repository) {
	t.Helper()
	master, err := repo.Reference(plumbing.Master, true)
	require.NoError(t, err)
	parent, err := repo.CommitObject(master.Hash())
	require.NoError(t, err)

	signature := object.Signature{Name: t.Name(), Email: "test@example.com", When: time.Unix(1, 0).UTC()}
	commitObject := repo.Storer.NewEncodedObject()
	require.NoError(t, (&object.Commit{
		Author:       signature,
		Committer:    signature,
		Message:      "advance master",
		TreeHash:     parent.TreeHash,
		ParentHashes: []plumbing.Hash{parent.Hash},
	}).Encode(commitObject))
	commitHash := storeGitObject(t, repo.Storer, commitObject)

	require.NoError(t, repo.Storer.SetReference(plumbing.NewHashReference(plumbing.Master, commitHash)))
	require.NoError(t, repo.Storer.SetReference(plumbing.NewHashReference(plumbing.HEAD, parent.Hash)))
}

func storeGitObject(t *testing.T, storer storage.Storer, encoded plumbing.EncodedObject) plumbing.Hash {
	t.Helper()
	hash, err := storer.SetEncodedObject(encoded)
	require.NoError(t, err)
	return hash
}

type gitTreeNode struct {
	files   []object.TreeEntry
	subdirs map[string]*gitTreeNode
}

func (n *gitTreeNode) add(t *testing.T, storer storage.Storer, parts []string, file GitFixtureFile) {
	t.Helper()
	if len(parts) == 1 {
		n.files = append(n.files, object.TreeEntry{
			Name: parts[0],
			Mode: file.Mode,
			Hash: WriteGitBlob(t, storer, file.Content),
		})
		return
	}
	if n.subdirs == nil {
		n.subdirs = map[string]*gitTreeNode{}
	}
	child, ok := n.subdirs[parts[0]]
	if !ok {
		child = &gitTreeNode{}
		n.subdirs[parts[0]] = child
	}
	child.add(t, storer, parts[1:], file)
}

func (n *gitTreeNode) write(t *testing.T, storer storage.Storer) plumbing.Hash {
	t.Helper()
	entries := slices.Clone(n.files)
	for name, subdir := range n.subdirs {
		entries = append(entries, object.TreeEntry{Name: name, Mode: filemode.Dir, Hash: subdir.write(t, storer)})
	}
	return WriteGitTree(t, storer, entries)
}
