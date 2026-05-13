/*
 * © 2026 Snyk Limited All rights reserved.
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

package oss_test

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// sharedCLIPath is the path to a single Snyk CLI binary shared across all smoke tests in
// this package. It is populated by TestMain when SMOKE_TESTS=1. Tests must not delete it.
var sharedCLIPath string

// TestMain downloads the Snyk CLI once for the whole package test run when SMOKE_TESTS=1.
// Test_Scan uses sharedCLIPath directly, avoiding a per-test download.
func TestMain(m *testing.M) {
	if os.Getenv(testsupport.SmokeTestEnvVar) == "" || os.Getenv("SMOKE_SHARD_4") == "" {
		os.Exit(m.Run())
	}

	cliDir, err := os.MkdirTemp("", "snyk-ls-oss-cli-shared-*")
	if err != nil {
		log.Fatalf("shared CLI temp dir failed: %v", err)
	}
	engine, err := testutil.NewMinimalEngine()
	if err != nil {
		log.Fatalf("shared CLI engine init failed: %v", err)
	}
	sharedCLIPath, err = downloadCLI(engine, cliDir)
	if err != nil {
		log.Fatalf("shared CLI download failed: %v", err)
	}
	log.Printf("shared CLI downloaded to: %s", sharedCLIPath)

	code := m.Run()
	os.RemoveAll(cliDir)
	os.Exit(code)
}

// downloadCLI downloads the Snyk CLI binary into cliDir using the provided engine's
// installer. It configures SettingCliPath and SettingAutomaticDownload, calls the
// installer, and returns the installed binary path.
func downloadCLI(engine workflow.Engine, cliDir string) (string, error) {
	conf := engine.GetConfiguration()
	discovery := &install.Discovery{}
	cliPath := filepath.Join(cliDir, discovery.ExecutableName(false))
	conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	er := error_reporting.NewTestErrorReporter(engine)
	resolver := testutil.DefaultConfigResolver(engine)
	installer := install.NewInstaller(engine, er, func() *http.Client { return http.DefaultClient }, resolver)
	return installer.Install(ctx)
}
