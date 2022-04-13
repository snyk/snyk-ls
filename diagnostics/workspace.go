package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/lsp"
)

var registeredDocsMutex = &sync.Mutex{}

func registerAllFilesFromWorkspace(workspaceUri sglsp.DocumentURI) error {
	// this is not a mistake - eclipse reports workspace folders with `file:` pre-prended
	workspace, err :=
		filepath.Abs(
			strings.ReplaceAll(strings.ReplaceAll(string(workspaceUri), "file://", ""), "file:", ""),
		)

	if err != nil {
		return err
	}

	var patterns []string
	patterns, err = loadIgnorePatterns(workspace)
	if err != nil {
		return err
	}

	return filepath.WalkDir(workspace, func(path string, dirEntry os.DirEntry, _ error) error {
		if dirEntry == nil || dirEntry.IsDir() {
			return nil
		}

		if ignored(patterns, path) {
			return nil
		}

		content, err := os.ReadFile(path)
		file := sglsp.TextDocumentItem{
			URI:  sglsp.DocumentURI("file://" + path),
			Text: string(content),
		}

		registeredDocsMutex.Lock()
		RegisterDocument(file)
		registeredDocsMutex.Unlock()

		return err
	})
}

func loadIgnorePatterns(workspace string) ([]string, error) {
	var ignores = ""
	log.Debug().
		Str("method", "loadIgnorePatterns").
		Str("workspace", workspace).
		Msg("searching for ignore files")
	err := filepath.WalkDir(workspace, func(path string, dirEntry os.DirEntry, _ error) error {
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

	patterns := strings.Split(ignores, "\n")
	log.Debug().Interface("ignorePatterns", patterns).Msg("Loaded ignore patterns")
	return patterns, nil
}

func ignored(patterns []string, path string) bool {
	ignored := false
	gitIgnore := ignore.CompileIgnoreLines(patterns...)
	for _, pattern := range patterns {
		ignored = gitIgnore.MatchesPath(path)
		if ignored {
			log.Trace().Str("method", "ignored").Str("pattern", pattern).Str("path", path).Msg("matched")
			return true
		}
		log.Trace().Str("method", "ignored").Str("pattern", pattern).Str("path", path).Msg("not matched")
	}
	return false
}

func workspaceDiagnostics(workspaceUri sglsp.DocumentURI, wg *sync.WaitGroup) {
	defer wg.Done()

	var diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic
	var codeLenses map[sglsp.DocumentURI][]sglsp.CodeLens

	err := registerAllFilesFromWorkspace(workspaceUri)
	if err != nil {
		log.Error().Err(err).
			Str("method", "workspaceDiagnostics").
			Msg("Error occurred while registering files from workspace")
	}

	diagnostics, codeLenses = fetchAllRegisteredDocumentDiagnostics(workspaceUri, lsp.ScanLevelWorkspace)
	addToCache(diagnostics, codeLenses)
}

func WorkspaceScan(workspaceFolders []lsp.WorkspaceFolders) {
	var wg sync.WaitGroup

	for _, workspace := range workspaceFolders {
		wg.Add(1)
		go workspaceDiagnostics(workspace.Uri, &wg)
	}

	wg.Wait()
	log.Info().Str("method", "Workspace").
		Msg("Workspace scan completed")
}
