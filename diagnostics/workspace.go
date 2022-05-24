package diagnostics

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/instrumentation"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var scannedWorkspaceFolders = sync.Map{}

func getWorkspaceFiles(workspaceURI sglsp.DocumentURI) (files []sglsp.DocumentURI, err error) {
	workspace, err := filepath.Abs(uri.PathFromUri(workspaceURI))

	if err != nil {
		return files, err
	}

	var patterns []string
	patterns, err = loadIgnorePatterns(workspace)
	if err != nil {
		return files, err
	}

	gitIgnore := ignore.CompileIgnoreLines(patterns...)
	err = filepath.WalkDir(workspace, func(path string, dirEntry os.DirEntry, _ error) error {
		if dirEntry == nil || dirEntry.IsDir() {
			if ignored(gitIgnore, path) {
				return filepath.SkipDir
			}
			return nil
		}

		if ignored(gitIgnore, path) {
			return nil
		}

		files = append(files, uri.PathToUri(path))
		return err
	})
	if err != nil {
		return files, err
	}
	return files, nil
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

func loadIgnorePatterns(workspace string) (patterns []string, err error) {
	var ignores = ""
	log.Debug().
		Str("method", "loadIgnorePatterns").
		Str("workspace", workspace).
		Msg("searching for ignore files")
	err = filepath.WalkDir(workspace, func(path string, dirEntry os.DirEntry, _ error) error {
		if dirEntry == nil || dirEntry.IsDir() {
			return nil
		}

		if !(strings.HasSuffix(path, ".gitignore") || strings.HasSuffix(path, ".dcignore")) {
			return nil
		}
		log.Debug().Str("method", "loadIgnorePatterns").Str("file", path).Msg("found ignore file")
		content, err := os.ReadFile(path)
		if err != nil {
			log.Err(err).Msg("Can't read" + path)
		}
		ignores += string(content)
		return err
	})

	if err != nil {
		return nil, err
	}

	patterns = strings.Split(ignores, "\n")
	log.Debug().Interface("ignorePatterns", patterns).Msg("Loaded ignore patterns")
	return patterns, nil
}

func ignored(gitIgnore *ignore.GitIgnore, path string) bool {
	ignored := false
	ignored = gitIgnore.MatchesPath(path)
	if ignored {
		log.Trace().Str("method", "ignored").Str("path", path).Msg("matched")
		return true
	}
	log.Trace().Str("method", "ignored").Str("path", path).Msg("not matched")
	return false
}

func workspaceDiagnostics(ctx context.Context, workspace lsp.WorkspaceFolder, wg *sync.WaitGroup) {
	defer wg.Done()

	diagnostics := fetchAllRegisteredDocumentDiagnostics(ctx, workspace.Uri, lsp.ScanLevelWorkspace)
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
	method := "WorkspaceScan"
	s := instrumentation.NewTransaction(ctx, method, method)
	defer s.Finish()

	preconditions.EnsureReadyForAnalysisAndWait(s.Context())
	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Starting workspace scan."})
	defer notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Workspace scan completed."})
	var wg sync.WaitGroup
	for _, workspace := range workspaceFolders {
		wg.Add(1)
		go workspaceDiagnostics(s.Context(), workspace, &wg)
	}

	wg.Wait()
	log.Info().Str("method", "Workspace").
		Msg("Workspace scan completed")
}
