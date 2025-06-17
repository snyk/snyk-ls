/*
 * © 2025 Snyk Limited
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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/pkg/browser"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/mcp_extension/networking"
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
	return filepath.Clean(folder)
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

	return t.isFolderTrusted(folder)
}

func (t *FolderTrust) isFolderTrusted(folder string) bool {
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
	result := t.config.Get(TrustedFoldersConfigKey)
	switch v := result.(type) {
	case []string:
		return v
	case []interface{}:
		var trustedFolders []string
		for _, item := range v {
			if folderPath, ok := item.(string); ok {
				trustedFolders = append(trustedFolders, folderPath)
			}
		}
		return trustedFolders
	default:
		return []string{}
	}
}

func (t *FolderTrust) AddTrustedFolder(folder string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.addTrustedFolder(folder)
}

func (t *FolderTrust) addTrustedFolder(folder string) {
	folder = normalizePath(folder)
	if t.isFolderTrusted(folder) {
		return
	}
	trustedFolders := t.trustedFolders()
	trustedFolders = append(trustedFolders, folder)
	t.config.Set(TrustedFoldersConfigKey, trustedFolders)
}

func (t *FolderTrust) HandleTrust(ctx context.Context, folderPath string, logger zerolog.Logger) (*mcp.CallToolResult, error) {
	resultChan := make(chan *mcp.CallToolResult)
	errorChan := make(chan error)

	loggerForTemplate := logger.With().Str("method", "HandleTrust").Logger()

	tmpl, err := template.New("trustPage").Parse(SnykTrustPage)
	if err != nil {
		loggerForTemplate.Error().Err(err).Msg("Failed to parse HTML template from trust.SnykTrustPage")
		return nil, fmt.Errorf("failed to parse HTML template from trust.SnykTrustPage: %w", err)
	}

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	defer func() {
		if server != nil {
			logger.Info().Msg("Trust handler exiting, ensuring server shutdown via defer")
			if err = server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error().Err(err).Msg("Error during deferred server shutdown")
			}
		}
	}()

	t.addHttpHandlers(logger, mux, folderPath, tmpl, resultChan, errorChan)

	serverUrl, err := networking.LoopbackURL()
	if err != nil {
		return nil, fmt.Errorf("failed to get default url: %w", err)
	}

	retries := 0
	for networking.IsPortInUse(serverUrl) && retries < 10 {
		time.Sleep(10 * time.Millisecond)
		retries++
	}
	rawUrl := serverUrl.String()
	listener, err := net.Listen("tcp", serverUrl.Host)

	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	go func() {
		logger.Info().Str("url", rawUrl).Msg("Starting trust confirmation server")
		if err = server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error().Err(err).Msg("HTTP server error")
			errorChan <- fmt.Errorf("HTTP server failed: %w", err)
		}
		logger.Info().Msg("Trust confirmation server stopped")
	}()

	browser.Stdout = logger
	err = browser.OpenURL(rawUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to open browser: %w", err)
	}

	logger.Info().Str("message", "Waiting for user action on "+rawUrl).Msg("Trust Handler")

	select {
	case res := <-resultChan:
		logger.Debug().Any("result", res).Msg("Received trust result from server")
		return res, nil
	case err = <-errorChan:
		logger.Warn().Err(err).Msg("Received cancel/error result from server")
		return nil, err
	case <-ctx.Done():
		logger.Info().Msg("Context canceled")
		return nil, ctx.Err()
	}
}

func (t *FolderTrust) addHttpHandlers(logger zerolog.Logger, mux *http.ServeMux, folderPath string, tmpl *template.Template, resultChan chan *mcp.CallToolResult, errorChan chan error) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageData := struct{ Path string }{Path: folderPath}
		tmpErr := tmpl.Execute(w, pageData)
		if tmpErr != nil {
			http.Error(w, "Failed to render page", http.StatusInternalServerError)
			logger.Error().Err(tmpErr).Msg("Failed to render HTML template")
			errorChan <- fmt.Errorf("failed to render HTML template")
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
		logger.Info().Msg("Operation canceled by user.")
		http.Error(w, "user canceled trust operation", http.StatusBadRequest)
		errorChan <- fmt.Errorf("user canceled trust operation for path: %s", folderPath)
	})
}
