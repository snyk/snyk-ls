/*
 * © 2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package scannercommon_test

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
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

func Test_RequireProductEnabled_DisabledNonReferenceErrorIsNonFailing(t *testing.T) {
	t.Parallel()
	for _, msg := range productDisabledMessages {
		t.Run(msg, func(t *testing.T) {
			t.Parallel()
			err := scannercommon.RequireProductEnabled(t.Context(), false, msg)
			require.Error(t, err)
			assert.True(t, utils.IsNonFailingScanError(err.Error()),
				"IsNonFailingScanError must be true for RequireProductEnabled(ctx, false, %q)", msg)
		})
	}
}

func Test_RequireProductEnabled_ContextContract(t *testing.T) {
	t.Parallel()

	unknownScanType := ctx2.DeltaScanType("Unknown")
	tests := []struct {
		name    string
		ctx     context.Context
		enabled bool
		wantErr bool
	}{
		{name: "reference context overrules disabled to always enabled", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), ctx2.Reference), wantErr: false},
		{name: "working directory context and disabled returns non failing errors", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), ctx2.WorkingDirectory), wantErr: true},
		{name: "missing scan type and disabled returns non failing errors", ctx: t.Context(), wantErr: true},
		{name: "unknown scan type and disabled returns non failing errors", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), unknownScanType), wantErr: true},
		{name: "reference context and enabled returns no error", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), ctx2.Reference), enabled: true},
		{name: "working directory context and enabled returns no error", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), ctx2.WorkingDirectory), enabled: true},
		{name: "missing scan type and enabled returns no error", ctx: t.Context(), enabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := scannercommon.RequireProductEnabled(tt.ctx, tt.enabled, utils.ErrSnykCodeNotEnabledForFolder)
			if tt.wantErr {
				require.EqualError(t, err, utils.ErrSnykCodeNotEnabledForFolder)
				assert.True(t, utils.IsNonFailingScanError(err.Error()))
				return
			}
			require.NoError(t, err)
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
	err := scannercommon.RequireProductEnabled(t.Context(), true, utils.ErrSnykCodeNotEnabledForFolder)
	assert.NoError(t, err)
}
