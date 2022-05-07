package diagnostics

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	ignore "github.com/sabhiram/go-gitignore"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var scannedWorkspaceFolders = sync.Map{}

func registerAllFilesFromWorkspace(
	ctx context.Context,
	workspaceUri sglsp.DocumentURI,
) (walkedFiles []string, err error) {
	workspace, err := filepath.Abs(uri.PathFromUri(workspaceUri))

	if err != nil {
		return nil, err
	}

	var patterns []string
	patterns, err = loadIgnorePatterns(ctx, workspace)
	if err != nil {
		return nil, err
	}

	gitIgnore := ignore.CompileIgnoreLines(patterns...)
	return walkedFiles, filepath.WalkDir(workspace, func(path string, dirEntry os.DirEntry, _ error) error {
		if dirEntry == nil || dirEntry.IsDir() {
			if ignored(gitIgnore, path) {
				return filepath.SkipDir
			}
			return nil
		}

		walkedFiles = append(walkedFiles, path)

		if ignored(gitIgnore, path) {
			return nil
		}

		file := sglsp.TextDocumentItem{URI: uri.PathToUri(path)}
		RegisterDocument(file)
		return err
	})
}

func IsWorkspaceFolderScanned(folder lsp.WorkspaceFolder) bool {
	_, found := scannedWorkspaceFolders.Load(folder)
	return found
}

func ClearWorkspaceFolderScanned() {
	scannedWorkspaceFolders = sync.Map{}
}

func setFolderScanned(folder lsp.WorkspaceFolder) {
	scannedWorkspaceFolders.Store(folder, true)
}

func removeFolderFromScanned(folder lsp.WorkspaceFolder) {
	scannedWorkspaceFolders.Delete(folder)
}

func loadIgnorePatterns(ctx context.Context, workspace string) (patterns []string, err error) {
	var ignores = ""
	logger.
		WithField("method", "loadIgnorePatterns").
		WithField("workspace", workspace).
		Debug(ctx, "searching for ignore files")

	err = filepath.WalkDir(workspace, func(path string, dirEntry os.DirEntry, _ error) error {
		if dirEntry == nil || dirEntry.IsDir() {
			return nil
		}

		if !(strings.HasSuffix(path, ".gitignore") || strings.HasSuffix(path, ".dcignore")) {
			return nil
		}
		logger.
			WithField("method", "loadIgnorePatterns").
			WithField("file", path).
			Debug(ctx, "found ignore file")
		content, err := os.ReadFile(path)
		if err != nil {
			logger.
				WithField("method", "loadIgnorePatterns").
				WithField("file", path).
				Error(ctx, "can't read file")
		}
		ignores += string(content)
		return err
	})

	if err != nil {
		return nil, err
	}

	patterns = strings.Split(ignores, "\n")
	logger.
		WithField("method", "loadIgnorePatterns").
		WithField("ignorePatterns", patterns).
		Debug(ctx, "loaded Ignore Patterns")
	return patterns, nil
}

func ignored(gitIgnore *ignore.GitIgnore, path string) bool {
	return gitIgnore.MatchesPath(path)
}

func workspaceDiagnostics(ctx context.Context, workspace lsp.WorkspaceFolder, wg *sync.WaitGroup) {
	defer wg.Done()

	var diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic

	_, err := registerAllFilesFromWorkspace(ctx, workspace.Uri)
	if err != nil {
		logger.
			WithField("method", "workspaceDiagnostics").
			WithField("workspace", workspace).
			WithError(err).
			Error(ctx, "couldn't register all files in workspace")
	}

	diagnostics = fetchAllRegisteredDocumentDiagnostics(ctx, workspace.Uri, lsp.ScanLevelWorkspace)
	addToCache(diagnostics)
	setFolderScanned(workspace)
	for documentURI, d := range diagnostics {
		notification.Send(lsp.PublishDiagnosticsParams{
			URI:         documentURI,
			Diagnostics: d,
		})
	}
}

func WorkspaceScan(ctx context.Context, workspaceFolders []lsp.WorkspaceFolder) {
	preconditions.EnsureReadyForAnalysisAndWait()
	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Starting workspace scan."})
	defer notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Workspace scan completed."})
	var wg sync.WaitGroup
	for _, workspace := range workspaceFolders {
		wg.Add(1)
		go workspaceDiagnostics(ctx, workspace, &wg)
	}

	wg.Wait()
	logger.WithField("method", "WorkspaceScan").Info(ctx, "Workspace scan completed")
}
