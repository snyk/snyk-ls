/*
 * © 2022-2025 Snyk Limited
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

package mcp

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/types"
)

type mcpServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

type mcpConfig struct {
	McpServers map[string]mcpServer `json:"mcpServers"`
}

//go:embed rules/always_apply.md
var snykRulesAlwaysApply string

//go:embed rules/smart_apply.md
var snykRulesSmartApply string

// getMcpArgs returns the arguments for MCP server
func getMcpArgs() []string {
	return []string{"mcp", "-t", "stdio"}
}

// getMcpEnv builds environment variables for MCP
func getMcpEnv(c *config.Config) map[string]string {
	env := make(map[string]string)

	// Add organization if configured
	org := c.Organization()
	if org != "" {
		env["SNYK_CFG_ORG"] = org
	}

	// Add API endpoint
	apiUrl := c.SnykApi()
	if apiUrl != "" {
		env["SNYK_API"] = apiUrl
	}

	// Add IDE name from integration environment
	ideName := c.Engine().GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT)
	if ideName != "" {
		env["IDE_CONFIG_PATH"] = ideName
	}

	// Add trusted folders (semicolon-separated)
	trustedFolders := c.TrustedFolders()
	if len(trustedFolders) > 0 {
		var folderPaths []string
		for _, folder := range trustedFolders {
			folderPaths = append(folderPaths, string(folder))
		}
		env["TRUSTED_FOLDERS"] = strings.Join(folderPaths, ";")
	}

	return env
}

// ConfigureMcp configures MCP for the appropriate IDE
func ConfigureMcp(c *config.Config) {
	if !c.IsAutoConfigureMcpEnabled() {
		return
	}
	logger := c.Logger().With().Str("method", "ConfigureMcp").Logger()

	ideName := strings.ToLower(c.Engine().GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT))

	if strings.Contains(ideName, "cursor") {
		configureCursor(c)
	} else if strings.Contains(ideName, "windsurf") {
		configureWindsurf(c)
	} else if strings.Contains(ideName, "visual studio code") {
		configureCopilot(c)
	} else {
		logger.Warn().Str("ideName", ideName).Msg("Unknown IDE, skipping MCP configuration")
	}
}

// configureCursor writes MCP configuration to Cursor's config file
func configureCursor(c *config.Config) {
	logger := c.Logger().With().Str("method", "configureCursor").Logger()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get user home directory")
		return
	}

	configPath := filepath.Join(homeDir, ".cursor", "mcp.json")
	command := c.CliSettings().Path()
	args := getMcpArgs()
	env := getMcpEnv(c)

	err = ensureMcpServerInJson(configPath, "Snyk", command, args, env, &logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to update Cursor MCP config")
		return
	}

	logger.Debug().Str("configPath", configPath).Msg("Ensured Cursor MCP config")

	configureRulesFiles(c, &logger, filepath.Join(".cursor", "rules", "snyk_rules.mdc"), ".cursor/rules/snyk_rules.mdc")
}

// configureWindsurf writes MCP configuration to Windsurf's config file
func configureWindsurf(c *config.Config) {
	logger := c.Logger().With().Str("method", "configureWindsurf").Logger()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get user home directory")
		return
	}

	baseDir := filepath.Join(homeDir, ".codeium", "windsurf")
	configPath := filepath.Join(baseDir, "mcp_config.json")

	// Check if Windsurf directory exists
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		logger.Debug().Str("baseDir", baseDir).Msg("Windsurf base directory not found, skipping MCP configuration")
		return
	}

	command := c.CliSettings().Path()
	args := getMcpArgs()
	env := getMcpEnv(c)

	err = ensureMcpServerInJson(configPath, "Snyk", command, args, env, &logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to update Windsurf MCP config")
		return
	}

	logger.Debug().Str("configPath", configPath).Msg("Ensured Windsurf MCP config")

	// Handle rules file management for Windsurf
	configureRulesFiles(c, &logger, filepath.Join(".windsurf", "rules", "snyk_rules.md"), ".windsurf/rules/snyk_rules.md")
}

// configureCopilot sends notification to VS Code extension to register MCP server
func configureCopilot(c *config.Config) {
	logger := c.Logger().With().Str("method", "configureCopilot").Logger()

	// For VS Code, we need to use the VS Code API (vscode.lm.registerMcpServerDefinitionProvider)
	// which can only be called from the extension. Send notification to extension.
	params := types.SnykConfigureMcpParams{
		Command: c.CliSettings().Path(),
		Args:    getMcpArgs(),
		Env:     getMcpEnv(c),
		IdeName: c.Engine().GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT),
	}

	logger.Debug().Interface("params", params).Msg("Sending MCP configuration to VS Code extension")
	go di.Notifier().Send(params)

	// Handle rules file management for VS Code Copilot
	configureRulesFiles(c, &logger, filepath.Join(".github", "instructions", "snyk_rules.instructions.md"), ".github/instructions/snyk_rules.instructions.md")
}

// ensureMcpServerInJson ensures the Snyk MCP server is configured in a JSON config file
func ensureMcpServerInJson(filePath, serverKey, command string, args []string, env map[string]string, logger *zerolog.Logger) error {
	config := mcpConfig{
		McpServers: make(map[string]mcpServer),
	}

	// Read existing config if it exists
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(data, &config); err != nil {
			logger.Warn().Err(err).Msg("Failed to parse existing MCP config, will recreate")
			config.McpServers = make(map[string]mcpServer)
		}
	}

	// Find existing Snyk server (case-insensitive)
	serverKeyLower := strings.ToLower(serverKey)
	var matchedKey string
	for key := range config.McpServers {
		if strings.ToLower(key) == serverKeyLower || strings.Contains(strings.ToLower(key), serverKeyLower) {
			matchedKey = key
			break
		}
	}

	keyToUse := serverKey
	if matchedKey != "" {
		keyToUse = matchedKey
	}

	// Merge environment variables (keep existing, override Snyk-specific ones)
	resultingEnv := make(map[string]string)
	if existing, ok := config.McpServers[keyToUse]; ok && existing.Env != nil {
		for k, v := range existing.Env {
			resultingEnv[k] = v
		}
	}

	// Override Snyk-specific environment variables
	snykKeys := []string{"SNYK_CFG_ORG", "SNYK_API", "IDE_CONFIG_PATH", "TRUSTED_FOLDERS"}
	for _, k := range snykKeys {
		if v, ok := env[k]; ok {
			resultingEnv[k] = v
		}
	}

	// Check if update is needed
	existing, exists := config.McpServers[keyToUse]
	needsWrite := !exists ||
		existing.Command != command ||
		!stringSlicesEqual(existing.Args, args) ||
		!mapsEqual(existing.Env, resultingEnv)

	if !needsWrite {
		return nil
	}

	// Update config
	config.McpServers[keyToUse] = mcpServer{
		Command: command,
		Args:    args,
		Env:     resultingEnv,
	}

	// Write config file
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// getRulesContent returns the appropriate rules content based on execution frequency
func getRulesContent(frequency string) string {
	if frequency == "On Code Generation" {
		return snykRulesAlwaysApply
	}
	return snykRulesSmartApply
}

// configureRulesFiles handles rules file management for all IDEs
func configureRulesFiles(c *config.Config, logger *zerolog.Logger, rulesRelativePath string, gitignoreEntry string) {
	frequency := c.GetSecureAtInceptionExecutionFrequency()
	if frequency == "Manual" {
		return
	}

	// Get workspace roots
	workspaceFolders := c.Workspace().Folders()
	if len(workspaceFolders) == 0 {
		logger.Debug().Msg("No workspace folders found, skipping rules file management")
		return
	}

	rulesContent := getRulesContent(frequency)

	for _, folder := range workspaceFolders {
		workspaceRoot := string(folder.Path())
		// Write rules file
		rulesPath := filepath.Join(workspaceRoot, rulesRelativePath)
		if err := ensureRulesFile(c, rulesPath, rulesContent); err != nil {
			logger.Error().Err(err).Str("workspace", workspaceRoot).Msg("Failed to write rules file")
			continue
		}

		// Update .gitignore
		gitignoreEntries := []string{gitignoreEntry}
		if err := ensureGitignore(c, workspaceRoot, gitignoreEntries); err != nil {
			logger.Error().Err(err).Str("workspace", workspaceRoot).Msg("Failed to update .gitignore")
		}
	}
}

// ensureRulesFile writes the rules file to the specified path
func ensureRulesFile(c *config.Config, rulesPath string, content string) error {
	// Create the directory if it doesn't exist
	dir := filepath.Dir(rulesPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		c.Logger().Error().Err(err).Msgf("Failed to create rules directory: %s", dir)
		return err
	}

	// Read existing file if it exists
	existingContent, err := os.ReadFile(rulesPath)
	if err == nil {
		// File exists, check if content is the same
		if string(existingContent) == content {
			c.Logger().Debug().Msgf("Rules file already up to date: %s", rulesPath)
			return nil
		}
	}

	// Write the rules file
	if err := os.WriteFile(rulesPath, []byte(content), 0644); err != nil {
		c.Logger().Error().Err(err).Msgf("Failed to write rules file: %s", rulesPath)
		return err
	}

	c.Logger().Info().Msgf("Rules file written: %s", rulesPath)
	return nil
}

// ensureGitignore adds entries to .gitignore if they don't exist
func ensureGitignore(c *config.Config, workspaceRoot string, entries []string) error {
	gitignorePath := filepath.Join(workspaceRoot, ".gitignore")

	// Read existing .gitignore
	existingContent, err := os.ReadFile(gitignorePath)
	if err != nil && !os.IsNotExist(err) {
		c.Logger().Error().Err(err).Msg("Failed to read .gitignore")
		return err
	}

	existingLines := strings.Split(string(existingContent), "\n")
	existingMap := make(map[string]bool)
	for _, line := range existingLines {
		existingMap[strings.TrimSpace(line)] = true
	}

	// Check which entries need to be added
	var entriesToAdd []string
	for _, entry := range entries {
		if !existingMap[entry] {
			entriesToAdd = append(entriesToAdd, entry)
		}
	}

	if len(entriesToAdd) == 0 {
		c.Logger().Debug().Msg(".gitignore already contains all required entries")
		return nil
	}

	// Append new entries
	var newContent strings.Builder
	newContent.WriteString(string(existingContent))
	if len(existingContent) > 0 && !strings.HasSuffix(string(existingContent), "\n") {
		newContent.WriteString("\n")
	}
	newContent.WriteString("\n# Snyk Security At Inception\n")
	for _, entry := range entriesToAdd {
		newContent.WriteString(entry + "\n")
	}

	if err := os.WriteFile(gitignorePath, []byte(newContent.String()), 0644); err != nil {
		c.Logger().Error().Err(err).Msg("Failed to write .gitignore")
		return err
	}

	c.Logger().Info().Msgf("Added %d entries to .gitignore", len(entriesToAdd))
	return nil
}
