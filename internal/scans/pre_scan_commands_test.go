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
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/testsupport"
)

func TestPreScanCommand_ExecutePreScanCommand(t *testing.T) {
	testsupport.NotOnWindows(t, "we call a posix file")
	logger := zerolog.New(zerolog.NewConsoleWriter(zerolog.ConsoleTestWriter(t)))
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	dir, err := os.Getwd()
	require.NoError(t, err)
	cut := NewPreScanCommand(conf, dir, "/bin/ls", &logger)

	err = cut.ExecutePreScanCommand(context.Background())

	require.NoError(t, err)
}
