/*
 * © 2024 Snyk Limited
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

package oss

import (
	"encoding/json"
	"fmt"

	"github.com/golang/mock/gomock"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
)

// ConvertJSONToIssuesWithoutDependencies converts OSS JSON output to Issues using the existing converter
// with minimal dependencies (test error reporter and mock learn service)
func ConvertJSONToIssuesWithoutDependencies(jsonOutput []byte) ([]types.Issue, error) {
	return ConvertJSONToIssuesWithLearnService(jsonOutput, nil)
}

// ConvertJSONToIssuesWithLearnService converts OSS JSON output to Issues using the existing converter
// with minimal dependencies. If learnService is nil, a mock will be used.
func ConvertJSONToIssuesWithLearnService(jsonOutput []byte, learnService learn.Service) ([]types.Issue, error) {
	var scanResults []scanResult
	var allIssues []types.Issue

	// Try parsing as array first
	if err := json.Unmarshal(jsonOutput, &scanResults); err != nil {
		// Try parsing as single object
		var singleResult scanResult
		if err := json.Unmarshal(jsonOutput, &singleResult); err != nil {
			return nil, fmt.Errorf("failed to parse OSS JSON: %w", err)
		}
		scanResults = append(scanResults, singleResult)
	}

	// Create minimal dependencies
	c := config.CurrentConfig()
	if c == nil {
		c = config.New()
		config.SetCurrentConfig(c)
	}

	// Use test error reporter
	errorReporter := error_reporting.NewTestErrorReporter()

	// Use provided learn service or create mock
	if learnService == nil {
		ctrl := gomock.NewController(&mockTB{})
		learnService = mock_learn.NewMockService(ctrl)
		learnService.(*mock_learn.MockService).
			EXPECT().
			GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, nil).AnyTimes()
	}

	// Empty package issue cache
	packageIssueCache := make(map[string][]types.Issue)

	for _, scanResult := range scanResults {
		// Determine paths
		workDir := types.FilePath("")
		targetFilePath := types.FilePath(scanResult.DisplayTargetFile)
		if targetFilePath == "" {
			targetFilePath = types.FilePath(scanResult.Path)
		}

		// Use the existing converter with empty file content (no AST parsing)
		issues := convertScanResultToIssues(c, &scanResult, workDir, targetFilePath, []byte{}, learnService, errorReporter, packageIssueCache)
		allIssues = append(allIssues, issues...)
	}

	return allIssues, nil
}

// mockTB is a minimal implementation of testing.TB for gomock
type mockTB struct{}

func (t *mockTB) Cleanup(func())                {}
func (t *mockTB) Error(args ...interface{})     {}
func (t *mockTB) Errorf(string, ...interface{}) {}
func (t *mockTB) Fail()                         {}
func (t *mockTB) FailNow()                      {}
func (t *mockTB) Failed() bool                  { return false }
func (t *mockTB) Fatal(args ...interface{})     {}
func (t *mockTB) Fatalf(string, ...interface{}) {}
func (t *mockTB) Helper()                       {}
func (t *mockTB) Log(args ...interface{})       {}
func (t *mockTB) Logf(string, ...interface{})   {}
func (t *mockTB) Name() string                  { return "ConvertJSONToIssuesWithoutDependencies" }
func (t *mockTB) Setenv(string, string)         {}
func (t *mockTB) Skip(args ...interface{})      {}
func (t *mockTB) SkipNow()                      {}
func (t *mockTB) Skipf(string, ...interface{})  {}
func (t *mockTB) Skipped() bool                 { return false }
func (t *mockTB) TempDir() string               { return "" }
