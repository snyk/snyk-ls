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

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/scannercommon"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func Test_IsProductEnabledForScan_ContextContract(t *testing.T) {
	t.Parallel()

	unknownScanType := ctx2.DeltaScanType("Unknown")
	tests := []struct {
		name        string
		ctx         context.Context
		enabled     bool
		wantEnabled bool
	}{
		{name: "reference context overrules disabled to always enabled", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), ctx2.Reference), wantEnabled: true},
		{name: "working directory context and disabled returns disabled", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), ctx2.WorkingDirectory), wantEnabled: false},
		{name: "missing scan type and disabled returns disabled", ctx: t.Context(), wantEnabled: false},
		{name: "unknown scan type and disabled returns disabled", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), unknownScanType), wantEnabled: false},
		{name: "reference context and enabled returns enabled", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), ctx2.Reference), enabled: true, wantEnabled: true},
		{name: "working directory context and enabled returns enabled", ctx: ctx2.NewContextWithDeltaScanType(t.Context(), ctx2.WorkingDirectory), enabled: true, wantEnabled: true},
		{name: "missing scan type and enabled returns enabled", ctx: t.Context(), enabled: true, wantEnabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			resolver := mock_types.NewMockConfigResolverInterface(ctrl)
			resolver.EXPECT().IsProductEnabledForFolder(product.ProductCode, gomock.Any()).Return(tt.enabled)
			folderConfig := &types.FolderConfig{}
			assert.Equal(t, tt.wantEnabled, scannercommon.IsProductEnabledForScan(tt.ctx, resolver, product.ProductCode, folderConfig))
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
