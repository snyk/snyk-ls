package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var scannedWorkspaceFolders = sync.Map{}

func registerAllFilesFromWorkspace(workspaceUri sglsp.DocumentURI) (walkedFiles []string, err error) {
	workspace, err := filepath.Abs(uri.PathFromUri(workspaceUri))

	if err != nil {
		return nil, err
	}

	var patterns []string
	patterns, err = loadIgnorePatterns(workspace)
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

func workspaceDiagnostics(workspace lsp.WorkspaceFolder, wg *sync.WaitGroup) {
	defer wg.Done()

	var diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic

	_, err := registerAllFilesFromWorkspace(workspace.Uri)
	if err != nil {
		log.Error().Err(err).
			Str("method", "workspaceDiagnostics").
			Msg("Error occurred while registering files from workspace")
	}

	diagnostics = fetchAllRegisteredDocumentDiagnostics(workspace.Uri, lsp.ScanLevelWorkspace)
	addToCache(diagnostics)
	setFolderScanned(workspace)
	for documentURI, d := range diagnostics {
		notification.Send(lsp.PublishDiagnosticsParams{
			URI:         documentURI,
			Diagnostics: d,
		})
	}
}

func WorkspaceScan(workspaceFolders []lsp.WorkspaceFolder) {
	preconditions.EnsureReadyForAnalysisAndWait()
	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Starting workspace scan."})
	defer notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Workspace scan completed."})
	var wg sync.WaitGroup
	for _, workspace := range workspaceFolders {
		wg.Add(1)
		go workspaceDiagnostics(workspace, &wg)
	}

	wg.Wait()
	log.Info().Str("method", "Workspace").
		Msg("Workspace scan completed")
}
