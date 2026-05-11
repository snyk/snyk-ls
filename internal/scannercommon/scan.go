/*
 * © 2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

// Package scannercommon holds shared helpers for ProductScanner implementations.
package scannercommon

import (
	"context"
	"errors"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/types"
)

// ResolveFolderAndScanType returns FolderConfig, the delta/working-directory scan type label,
// and the workspace folder path from that config.
func ResolveFolderAndScanType(ctx context.Context) (*types.FolderConfig, string, types.FilePath, error) {
	workspaceFolderConfig, ok := ctx2.FolderConfigFromContext(ctx)
	if !ok || workspaceFolderConfig == nil {
		return nil, "", types.FilePath(""), errors.New(utils.ErrFolderConfigNotInContext)
	}
	scanType := "WorkingDirectory"
	if deltaScanType, ok := ctx2.DeltaScanTypeFromContext(ctx); ok {
		scanType = deltaScanType.String()
	}
	return workspaceFolderConfig, scanType, workspaceFolderConfig.FolderPath, nil
}

// LoggerWithProductScanFields returns a child logger carrying standard ProductScanner
// structured fields: method, pathToScan, workspaceFolder, scanType.
func LoggerWithProductScanFields(
	base *zerolog.Logger,
	method string,
	pathToScan types.FilePath,
	workspaceFolder types.FilePath,
	scanType string,
) zerolog.Logger {
	return base.With().
		Str("method", method).
		Str("pathToScan", string(pathToScan)).
		Str("workspaceFolder", string(workspaceFolder)).
		Str("scanType", scanType).
		Logger()
}

// RequireProductEnabled returns an error when the product is not enabled for the folder.
func RequireProductEnabled(enabled bool, errNotEnabledForFolder string) error {
	if !enabled {
		return errors.New(errNotEnabledForFolder)
	}
	return nil
}

// RequireAuthToken logs and returns an error when no CLI/API token is configured.
func RequireAuthToken(conf configuration.Configuration, log zerolog.Logger) error {
	if config.GetToken(conf) == "" {
		log.Info().Msg(utils.MsgNotAuthenticatedNoScan)
		return errors.New(utils.MsgNotAuthenticatedNoScan)
	}
	return nil
}
