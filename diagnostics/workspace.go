package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

var registeredDocsMutex = &sync.Mutex{}
var scannedWorkspaceFoldersMutex = &sync.Mutex{}
var scannedWorkspaceFolders = make(map[lsp.WorkspaceFolder]bool)

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
	scannedWorkspaceFoldersMutex.Lock()
	defer scannedWorkspaceFoldersMutex.Unlock()
	return scannedWorkspaceFolders[folder]
}

func ClearWorkspaceFolderScanned() {
	scannedWorkspaceFoldersMutex.Lock()
	defer scannedWorkspaceFoldersMutex.Unlock()
	scannedWorkspaceFolders = make(map[lsp.WorkspaceFolder]bool)
}

func setFolderScanned(folder lsp.WorkspaceFolder) {
	scannedWorkspaceFoldersMutex.Lock()
	scannedWorkspaceFolders[folder] = true
	scannedWorkspaceFoldersMutex.Unlock()
}

func removeFolderFromScanned(folder lsp.WorkspaceFolder) {
	scannedWorkspaceFoldersMutex.Lock()
	delete(scannedWorkspaceFolders, folder)
	scannedWorkspaceFoldersMutex.Unlock()
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
}

func WorkspaceScan(workspaceFolders []lsp.WorkspaceFolder) {
	var wg sync.WaitGroup

	for _, workspace := range workspaceFolders {
		wg.Add(1)
		go workspaceDiagnostics(workspace, &wg)
	}

	wg.Wait()
	log.Info().Str("method", "Workspace").
		Msg("Workspace scan completed")
}
