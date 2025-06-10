/*
 * 2025 Snyk Limited
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

package trust

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/pkg/browser"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

const (
	TrustedFoldersConfigKey = "TRUSTED_FOLDERS"
	DisableTrustFlag        = "disable-trust"
)

type FolderTrust struct {
	logger *zerolog.Logger
	config configuration.Configuration
	mutex  sync.RWMutex
}

//go:embed trust.html
var SnykTrustPage string

func NewFolderTrust(logger *zerolog.Logger, config configuration.Configuration) *FolderTrust {
	return &FolderTrust{
		logger: logger,
		config: config,
	}
}

func normalizePath(folder string) string {
	return path.Clean(folder)
}

func folderContains(folderPath string, path string) bool {
	filePathSeparator := string(filepath.Separator)
	cleanPath := normalizePath(path)
	cleanFolderPath := normalizePath(folderPath)
	if !strings.HasSuffix(cleanFolderPath, filePathSeparator) {
		cleanFolderPath += filePathSeparator
	}

	// Check if the path is on a case-insensitive filesystem
	if runtime.GOOS == "windows" {
		cleanPath = strings.ToLower(cleanPath)
		cleanFolderPath = strings.ToLower(cleanFolderPath)
	}

	return strings.HasPrefix(cleanPath, cleanFolderPath) ||
		strings.HasPrefix(cleanPath+filePathSeparator, cleanFolderPath)
}

func (t *FolderTrust) IsFolderTrusted(folder string) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	for _, trustedFolder := range t.trustedFolders() {
		if folderContains(trustedFolder, folder) {
			return true
		}
	}
	return false
}

func (t *FolderTrust) TrustedFolders() []string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.trustedFolders()
}

func (t *FolderTrust) trustedFolders() []string {
	rawRes := t.config.Get(TrustedFoldersConfigKey)
	trustedFolders, ok := rawRes.([]string)
	if !ok {
		t.logger.Error().Msg("incorrect type stored for trusted folders")
		return []string{}
	}
	return trustedFolders
}

func (t *FolderTrust) AddTrustedFolder(folder string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.addTrustedFolder(folder)
}

func (t *FolderTrust) addTrustedFolder(folder string) {
	trustedFolders := t.trustedFolders()
	folder = normalizePath(folder)
	if slices.Contains(trustedFolders, folder) {
		return
	}
	trustedFolders = append(trustedFolders, folder)
	t.config.Set(TrustedFoldersConfigKey, trustedFolders)
}

func (t *FolderTrust) HandleTrust(ctx context.Context, folderPath string, logger zerolog.Logger) (*mcp.CallToolResult, error) {
	resultChan := make(chan *mcp.CallToolResult)
	errorChan := make(chan error)

	loggerForTemplates := logger.With().Str("method", "snykTrustHandler_template_parsing").Logger()

	tmpl, err := template.New("trustPage").Parse(SnykTrustPage)
	if err != nil {
		loggerForTemplates.Error().Err(err).Msg("Failed to parse HTML template from trust.SnykTrustPage")
		return nil, fmt.Errorf("failed to parse HTML template from trust.SnykTrustPage: %w", err)
	}

	mux := http.NewServeMux()
	var server *http.Server

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageData := struct{ Path string }{Path: folderPath}
		tmpErr := tmpl.Execute(w, pageData)
		if tmpErr != nil {
			http.Error(w, "Failed to render page", http.StatusInternalServerError)
			logger.Error().Err(tmpErr).Msg("Failed to render HTML template")
		}
	})

	mux.HandleFunc("/trust", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		logger.Info().Str("path", folderPath).Msg("User chose to trust folder")
		t.AddTrustedFolder(folderPath)

		logger.Info().Msg("Folder trusted successfully.")
		resultChan <- mcp.NewToolResultText("Folder '" + folderPath + "' is now trusted.")
	})

	mux.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		logger.Info().Str("path", folderPath).Msg("User chose not to trust folder")
		logger.Info().Msg("Operation cancelled by user.")
		errorChan <- fmt.Errorf("user cancelled trust operation for path: %s", folderPath)
	})

	listener, tmplErr := net.Listen("tcp", "127.0.0.1:0") // Listen on loopback interface
	if tmplErr != nil {
		return nil, fmt.Errorf("failed to listen on a port: %w", tmplErr)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	serverUrl := fmt.Sprintf("http://127.0.0.1:%d", port)

	server = &http.Server{Handler: mux}
	defer func() {
		if server != nil {
			logger.Info().Msg("Trust handler exiting, ensuring server shutdown via defer")
			if err = server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error().Err(err).Msg("Error during deferred server shutdown")
			}
		}
	}()

	go func() {
		logger.Info().Str("url", serverUrl).Msg("Starting trust confirmation server")
		if err = server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error().Err(err).Msg("HTTP server error")
			select {
			case errorChan <- fmt.Errorf("HTTP server failed: %w", err):
			default:
			}
		}
		logger.Info().Msg("Trust confirmation server stopped")
	}()

	browser.Stdout = os.Stderr
	_ = browser.OpenURL(serverUrl)

	logger.Info().Str("message", "Waiting for user action on "+serverUrl).Msg("Trust Handler")

	select {
	case res := <-resultChan:
		logger.Debug().Any("result", res).Msg("Received trust result from server")
		return res, nil
	case err = <-errorChan:
		logger.Warn().Err(err).Msg("Received cancel/error result from server")
		return nil, err
	case <-ctx.Done():
		logger.Info().Msg("Context cancelled")
		return nil, ctx.Err()
	}
}
