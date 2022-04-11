package diagnostics

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/snyk/snyk-ls/lsp"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
)

var mutex = &sync.Mutex{}

func registerAllFilesFromWorkspace(workspaceUri sglsp.DocumentURI) error {
	workspace, err := filepath.Abs(strings.ReplaceAll(
		string(workspaceUri),
		"file://", ""),
	)

	if err != nil {
		return err
	}

	return filepath.Walk(workspace, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		content, _ := os.ReadFile(path)
		file := sglsp.TextDocumentItem{
			URI:  sglsp.DocumentURI("file://" + path),
			Text: string(content),
		}

		mutex.Lock()
		RegisterDocument(file)
		mutex.Unlock()

		return err
	})
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

	diagnostics, codeLenses = fetchAllRegisteredDocumentDiagnostics(workspaceUri, ScanWorkspace)
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
