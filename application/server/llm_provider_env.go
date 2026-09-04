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

// Package server implements the server functionality
package server

import (
	"os"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/types"
)

// llmProviderBaseUrlEnvVar maps an LLM provider to the environment variable the
// Snyk Remediation Agent's CLI extension reads its custom base URL from. openai
// intentionally has no entry: the CLI extension has no base-URL env var for it, so
// a custom endpoint chosen with the openai provider is persisted and echoed back in
// the dialog but never exported to the process environment.
var llmProviderBaseUrlEnvVar = map[string]string{ //nolint:gochecknoglobals // effectively a package-level constant — immutable after init
	"anthropic": "ANTHROPIC_BASE_URL",
	"vertex":    "VERTEX_BASE_URL",
	"litellm":   "LITELLM_BASE_URL",
	"ollama":    "OLLAMA_HOST",
}

// llmProviderEnvManager manages the LLM provider environment variable state.
// It holds the mutex, the applied-env-var tracking, and the reconcile-pending flag
// as struct fields. It takes osSetenv/osUnsetenv-equivalent functions as injectable fields
// (function-typed struct fields defaulting to os.Setenv/os.Unsetenv) so tests can
// inject fakes instead of swapping package-level osSetenv/osUnsetenv vars.
type llmProviderEnvManager struct {
	mu               sync.Mutex
	appliedEnvVar    string
	reconcilePending atomic.Bool
	setenv           func(key, value string) error
	unsetenv         func(key string) error
}

// newLlmProviderEnvManager creates a new llmProviderEnvManager with default os functions.
func newLlmProviderEnvManager() *llmProviderEnvManager {
	return &llmProviderEnvManager{
		setenv:   os.Setenv,
		unsetenv: os.Unsetenv,
	}
}

// ApplyConfig persists the developer's chosen LLM provider, model and
// custom API endpoint for autonomous remediation. It never touches the API key -
// that continues to come only from the developer's own process environment.
//
// The model goes through the identical persist path as provider and base URL -
// ollama and litellm have no default model in remy-cli-extension, so without it
// those two providers would be unusable. Unlike base URL, the model has no
// environment-variable side effect here: buildRemyFixConfig reads it and sets it
// as a GAF config key at fix time, the same lever used for provider.
//
// It never unsets an environment variable it did not itself previously set.
func (m *llmProviderEnvManager) ApplyConfig(conf configuration.Configuration, logger *zerolog.Logger, settings map[string]*types.ConfigSetting) {
	provider, providerOk := settingStr(settings, types.SettingLlmProvider)
	baseUrl, baseUrlOk := settingStr(settings, types.SettingLlmBaseUrl)
	model, modelOk := settingStr(settings, types.SettingLlmModel)
	if !providerOk && !baseUrlOk && !modelOk {
		return
	}

	m.mu.Lock()
	if providerOk {
		types.SetGlobalUser(conf, types.SettingLlmProvider, provider)
	}
	if baseUrlOk {
		types.SetGlobalUser(conf, types.SettingLlmBaseUrl, baseUrl)
	}
	if modelOk {
		types.SetGlobalUser(conf, types.SettingLlmModel, model)
	}
	m.mu.Unlock()

	m.reconcileEnv(conf, logger)
}

// reconcileEnv syncs the process env vars with the currently persisted LLM provider/base URL.
// gafRunner's Remy invocation holds the remediation package's LLM provider env lock for
// reading for its whole (potentially minutes-long) run, so this never blocks the caller on that:
// it applies synchronously when the lock is free, otherwise defers to a single coalesced
// background worker and returns immediately. The worker always re-reads live config at the
// moment it finally acquires the lock, so it converges on whatever is latest then - never
// a stale snapshot from when it was scheduled.
func (m *llmProviderEnvManager) reconcileEnv(conf configuration.Configuration, logger *zerolog.Logger) {
	applied := remediation.TryWithLLMProviderEnvLock(func() {
		m.applyEnvLocked(conf, logger)
	})
	if applied {
		return
	}

	if !m.reconcilePending.CompareAndSwap(false, true) {
		return
	}
	go func() {
		remediation.WithLLMProviderEnvLock(func() {
			m.reconcilePending.Store(false)
			m.applyEnvLocked(conf, logger)
		})
	}()
}

// SettingsSnapshot reads provider and baseUrl as one pair under the manager's mutex,
// the same lock the persist step uses. Reading them independently would risk a torn pair:
// a concurrent persist call could land between the two reads and pair one call's provider
// with another call's baseUrl.
func (m *llmProviderEnvManager) SettingsSnapshot(conf configuration.Configuration) (provider, baseUrl string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return types.GetGlobalString(conf, types.SettingLlmProvider), types.GetGlobalString(conf, types.SettingLlmBaseUrl)
}

// applyEnvLocked must be called with the remediation package's LLM provider env lock
// held for writing (see remediation.TryWithLLMProviderEnvLock / remediation.WithLLMProviderEnvLock).
// It never unsets appliedEnvVar unless this process itself previously set it - a provider
// recorded in conf that this process never applied (e.g. loaded from disk before this
// function ever ran) must never justify clearing a developer's own environment variable.
func (m *llmProviderEnvManager) applyEnvLocked(conf configuration.Configuration, logger *zerolog.Logger) {
	provider, baseUrl := m.SettingsSnapshot(conf)
	newEnvVar, newHasEnvVar := llmProviderBaseUrlEnvVar[provider]

	if m.appliedEnvVar != "" && (!newHasEnvVar || newEnvVar != m.appliedEnvVar || baseUrl == "") {
		if err := m.unsetenv(m.appliedEnvVar); err != nil {
			logger.Err(err).Msgf("couldn't unset env variable %s", m.appliedEnvVar)
		} else {
			m.appliedEnvVar = ""
		}
	}
	if newHasEnvVar && baseUrl != "" {
		if err := m.setenv(newEnvVar, baseUrl); err != nil {
			logger.Err(err).Msgf("couldn't set env variable %s", newEnvVar)
		} else {
			m.appliedEnvVar = newEnvVar
		}
	}
}

// GetAppliedEnvVar returns the currently applied environment variable.
// For testing purposes only.
func (m *llmProviderEnvManager) GetAppliedEnvVar() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.appliedEnvVar
}

// SetAppliedEnvVar sets the applied environment variable.
// For testing purposes only.
func (m *llmProviderEnvManager) SetAppliedEnvVar(envVar string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appliedEnvVar = envVar
}
