/*
 * © 2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package scannercommon_test

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/utils"
	"github.com/snyk/snyk-ls/internal/scannercommon"
)

// productDisabledMessages are every errNotEnabledForFolder string passed from ProductScanner
// callers into RequireProductEnabled; they must stay aligned with utils.IsNonFailingScanError.
var productDisabledMessages = []string{
	utils.ErrSnykCodeNotEnabledForFolder,
	utils.ErrSnykIacNotEnabledForFolder,
	utils.ErrSnykOssNotEnabledForFolder,
	utils.ErrSnykSecretsNotEnabledForFolder,
}

func Test_RequireProductEnabled_ErrorIsNonFailing(t *testing.T) {
	t.Parallel()
	for _, msg := range productDisabledMessages {
		t.Run(msg, func(t *testing.T) {
			t.Parallel()
			err := scannercommon.RequireProductEnabled(false, msg)
			require.Error(t, err)
			assert.True(t, utils.IsNonFailingScanError(err.Error()),
				"IsNonFailingScanError must be true for RequireProductEnabled(false, %q)", msg)
		})
	}
}

func Test_RequireAuthToken_NoTokenErrorIsNonFailing(t *testing.T) {
	t.Parallel()
	conf := configuration.NewWithOpts()
	err := scannercommon.RequireAuthToken(conf, zerolog.Nop())
	require.Error(t, err)
	assert.True(t, utils.IsNonFailingScanError(err.Error()),
		"IsNonFailingScanError must be true for RequireAuthToken with empty token")
}

func Test_RequireProductEnabled_EnabledReturnsNil(t *testing.T) {
	t.Parallel()
	err := scannercommon.RequireProductEnabled(true, utils.ErrSnykCodeNotEnabledForFolder)
	assert.NoError(t, err)
}
