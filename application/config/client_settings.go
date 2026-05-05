/*
 * © 2022 Snyk Limited All rights reserved.
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

package config

import (
	"os"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/internal/types"
)

const (
	ActivateSnykOssKey     = "ACTIVATE_SNYK_OPEN_SOURCE"
	ActivateSnykCodeKey    = "ACTIVATE_SNYK_CODE"
	ActivateSnykIacKey     = "ACTIVATE_SNYK_IAC"
	ActivateSnykAdvisorKey = "ACTIVATE_SNYK_ADVISOR"
	ActivateSnykSecretsKey = "ACTIVATE_SNYK_SECRETS"
	SendErrorReportsKey    = "SEND_ERROR_REPORTS"
	Organization           = "SNYK_CFG_ORG"
)

func ClientSettingsFromEnv(conf configuration.Configuration, logger *zerolog.Logger) {
	productEnablementFromEnv(conf, logger)
	errorReportsEnablementFromEnv(conf)
	orgFromEnv(conf)
}

func orgFromEnv(conf configuration.Configuration) {
	org, exists := os.LookupEnv(Organization)
	if exists {
		SetOrganization(conf, org)
	}
}

func errorReportsEnablementFromEnv(conf configuration.Configuration) {
	errorReports := os.Getenv(SendErrorReportsKey)
	// The env var SEND_ERROR_REPORTS uses a custom name that GAF's auto-env binding
	// doesn't know about. Explicitly map it so the value overrides the flagset default.
	if errorReports == "false" {
		conf.Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), false)
	} else if errorReports != "" {
		conf.Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), true)
	}
}

func productEnablementFromEnv(conf configuration.Configuration, logger *zerolog.Logger) {
	oss := os.Getenv(ActivateSnykOssKey)
	codeEnv := os.Getenv(ActivateSnykCodeKey)
	iac := os.Getenv(ActivateSnykIacKey)
	advisor := os.Getenv(ActivateSnykAdvisorKey)
	secretsEnv := os.Getenv(ActivateSnykSecretsKey)

	if oss != "" {
		parseBool, err := strconv.ParseBool(oss)
		if err != nil {
			logger.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse oss config %s", oss)
		}
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), parseBool)
	}

	if codeEnv != "" {
		parseBool, err := strconv.ParseBool(codeEnv)
		if err != nil {
			logger.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse code config %s", codeEnv)
		}
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), parseBool)
	}

	if iac != "" {
		parseBool, err := strconv.ParseBool(iac)
		if err != nil {
			logger.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse iac config %s", iac)
		}
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), parseBool)
	}

	if advisor != "" {
		parseBool, err := strconv.ParseBool(advisor)
		if err != nil {
			logger.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse advisor config %s", advisor)
		}
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykAdvisorEnabled), parseBool)
	}

	if secretsEnv != "" {
		parseBool, err := strconv.ParseBool(secretsEnv)
		if err != nil {
			logger.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse secrets config %s", secretsEnv)
		}
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), parseBool)
	}
}
