/*
 * Copyright 2022 Snyk Ltd.
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

	"github.com/rs/zerolog/log"
)

const (
	ActivateSnykOssKey       = "ACTIVATE_SNYK_OPEN_SOURCE"
	ActivateSnykCodeKey      = "ACTIVATE_SNYK_CODE"
	ActivateSnykIacKey       = "ACTIVATE_SNYK_IAC"
	ActivateSnykContainerKey = "ACTIVATE_SNYK_CONTAINER"
	ActivateSnykAdvisorKey   = "ACTIVATE_SNYK_ADVISOR"
	SendErrorReportsKey      = "SEND_ERROR_REPORTS"
	Organization             = "SNYK_CFG_ORG"
	EnableTelemetry          = "SNYK_CFG_DISABLE_ANALYTICS"
)

func (c *Config) clientSettingsFromEnv() {
	c.productEnablementFromEnv()
	c.errorReportsEnablementFromEnv()
	c.orgFromEnv()
	c.telemetryEnablementFromEnv()
	c.path = os.Getenv("PATH")
}

func (c *Config) orgFromEnv() {
	org := os.Getenv(Organization)
	if org != "" {
		c.organization = org
	}
}

func (c *Config) errorReportsEnablementFromEnv() {
	errorReports := os.Getenv(SendErrorReportsKey)
	if errorReports == "false" {
		c.SetErrorReportingEnabled(false)
	} else {
		c.SetErrorReportingEnabled(true)
	}
}

func (c *Config) productEnablementFromEnv() {
	oss := os.Getenv(ActivateSnykOssKey)
	code := os.Getenv(ActivateSnykCodeKey)
	iac := os.Getenv(ActivateSnykIacKey)
	container := os.Getenv(ActivateSnykContainerKey)
	advisor := os.Getenv(ActivateSnykAdvisorKey)

	if oss != "" {
		parseBool, err := strconv.ParseBool(oss)
		if err != nil {
			log.Warn().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse oss config %s", oss)
		}
		c.isSnykOssEnabled.Set(parseBool)
	}

	if code != "" {
		parseBool, err := strconv.ParseBool(code)
		if err != nil {
			log.Warn().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse code config %s", code)
		}
		c.isSnykCodeEnabled.Set(parseBool)
	}

	if iac != "" {
		parseBool, err := strconv.ParseBool(iac)
		if err != nil {
			log.Warn().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse iac config %s", iac)
		}
		c.isSnykIacEnabled.Set(parseBool)
	}

	if container != "" {
		parseBool, err := strconv.ParseBool(container)
		if err != nil {
			log.Warn().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse container config %s", container)
		}
		c.isSnykContainerEnabled.Set(parseBool)
	}
	if advisor != "" {
		parseBool, err := strconv.ParseBool(advisor)
		if err != nil {
			log.Warn().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse advisor config %s", advisor)
		}
		c.isSnykAdvisorEnabled.Set(parseBool)
	}
}
