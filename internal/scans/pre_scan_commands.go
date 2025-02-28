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

package scans

import (
	"context"
	"os/exec"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/semaphore"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
)

type PreScanCommand struct {
	conf               configuration.Configuration
	preScanCommandPath types.FilePath
	semaphore          *semaphore.Weighted
	logger             *zerolog.Logger
	workDir            types.FilePath
}

func NewPreScanCommand(conf configuration.Configuration, workDir types.FilePath, preScanCommandPath types.FilePath, logger *zerolog.Logger) *PreScanCommand {
	return &PreScanCommand{
		conf:               conf,
		workDir:            workDir,
		preScanCommandPath: preScanCommandPath,
		semaphore:          semaphore.NewWeighted(1),
		logger:             logger,
	}
}

func (p *PreScanCommand) ExecutePreScanCommand(ctx context.Context) error {
	if p.preScanCommandPath == "" {
		return nil
	}
	err := p.semaphore.Acquire(ctx, 1)
	if err != nil {
		p.logger.Error().Err(err).Msg("failed to acquire semaphore")
		return nil
	}
	logger := p.logger.With().Str("method", "ExecutePreScanCommand").Logger()
	logger.Info().Msgf("executing pre scan command [%s]", p.preScanCommandPath)

	// set deadline
	ctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, string(p.preScanCommandPath))
	cmd.Stderr = logger
	cmd.Stdout = logger
	err = cmd.Run()
	if err != nil {
		logger.Error().Err(err).Msgf("failed to execute pre-scan command %s", p.preScanCommandPath)
	}
	return err
}
