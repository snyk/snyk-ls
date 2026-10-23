/*
 * © 2022-2024 Snyk Limited
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

package code

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_getShardKey(t *testing.T) {
	testutil.UnitTest(t)
	const testToken = "TEST"
	t.Run("should return root path hash", func(t *testing.T) {
		// Case 1: rootPath exists
		sampleRootPath := "C:\\GIT\\root"
		// deepcode ignore HardcodedPassword/test: false positive
		token := testToken
		assert.Equal(t, util.Hash([]byte(sampleRootPath)), getShardKey(types.FilePath(sampleRootPath), token))
	})

	t.Run("should return token hash", func(t *testing.T) {
		// Case 2: rootPath empty, token exists
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := testToken
		assert.Equal(t, util.Hash([]byte(token)), getShardKey(types.FilePath(sampleRootPath), token))
	})

	t.Run("should return empty shard key", func(t *testing.T) {
		// Case 3: No token, no rootPath set
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := ""
		assert.Equal(t, "", getShardKey(types.FilePath(sampleRootPath), token))
	})
}

func TestIssueEnhancer_autofixShowDetailsFunc(t *testing.T) {
	engine := testutil.UnitTest(t)
	issueEnhancer := IssueEnhancer{
		instrumentor: performance.NewInstrumentor(),
		rootPath:     "/Users/user/workspace/blah",
		engine:       engine,
	}
	issue, _ := setupTestData(t)

	t.Run("returns CommandData with correct URI and range", func(t *testing.T) {
		commandDataFunc := issueEnhancer.autofixShowDetailsFunc(t.Context(), issue)
		commandData := commandDataFunc()

		assert.Equal(t, types.NavigateToRangeCommand, commandData.Title)
		assert.Equal(t, types.NavigateToRangeCommand, commandData.CommandId)
		actualURI, ok := commandData.Arguments[0].(string)
		require.True(t, ok)
		assertTestDataSnykURI(t, actualURI)
		assert.Equal(t, issue.Range, commandData.Arguments[1])
	})
}

func Test_addIssueActions(t *testing.T) {
	engine := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	issueEnhancer := IssueEnhancer{
		notifier:       mockNotifier,
		instrumentor:   performance.NewInstrumentor(),
		engine:         engine,
		configResolver: testutil.DefaultConfigResolver(engine),
	}

	var setupCodeSettings = func() {
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykLearnCodeActions), false)
		folderPath := types.FilePath("/test/issue-enhancer")
		engineConfig := engine.GetConfiguration()
		types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath, "test-org", true)
		types.SetSastSettings(engineConfig, folderPath, &sast_contract.SastResponse{
			SastEnabled:    true,
			AutofixEnabled: true,
		})
		resolver := testutil.DefaultConfigResolver(engine)
		issueEnhancer.folderConfig = &types.FolderConfig{
			FolderPath:     folderPath,
			ConfigResolver: resolver,
		}
	}

	var setupFakeIssues = func(isIgnored bool, isAutofixable bool) []types.Issue {
		return []types.Issue{
			&snyk.Issue{
				ID:               "SNYK-123",
				Range:            fakeRange,
				Severity:         types.High,
				Product:          product.ProductCode,
				IssueType:        types.CodeSecurityVulnerability,
				Message:          "This is a dummy error (severity error)",
				CodelensCommands: []types.CommandData{FakeCommand},
				CodeActions:      []types.CodeAction{&FakeCodeAction},
				IsIgnored:        isIgnored,
				AdditionalData: snyk.CodeIssueData{
					Key:           uuid.New().String(),
					IsAutofixable: isAutofixable,
				},
			},
		}
	}

	t.Run("Includes AI fixes if issue is not ignored", func(t *testing.T) {
		setupCodeSettings()
		fakeIssues := setupFakeIssues(false, true)

		issueEnhancer.addIssueActions(t.Context(), fakeIssues)

		issueData, ok := fakeIssues[0].GetAdditionalData().(snyk.CodeIssueData)
		require.True(t, ok)
		assert.True(t, issueData.HasAIFix)
		assert.Len(t, fakeIssues[0].GetCodelensCommands(), 2)
		assert.Len(t, fakeIssues[0].GetCodeActions(), 2)
	})

	t.Run("Does not include AI fixes if issue is not autofixable", func(t *testing.T) {
		setupCodeSettings()
		fakeIssues := setupFakeIssues(false, false)

		issueEnhancer.addIssueActions(t.Context(), fakeIssues)

		issueData, ok := fakeIssues[0].GetAdditionalData().(snyk.CodeIssueData)
		require.True(t, ok)
		assert.False(t, issueData.HasAIFix)
		assert.Len(t, fakeIssues[0].GetCodelensCommands(), 1)
		assert.Len(t, fakeIssues[0].GetCodeActions(), 1)
	})

	t.Run("Does not include AI fixes even if it is autofixable if issue is ignored", func(t *testing.T) {
		setupCodeSettings()
		fakeIssues := setupFakeIssues(true, true)

		issueEnhancer.addIssueActions(t.Context(), fakeIssues)

		issueData, ok := fakeIssues[0].GetAdditionalData().(snyk.CodeIssueData)
		require.True(t, ok)
		assert.False(t, issueData.HasAIFix)
		assert.Len(t, fakeIssues[0].GetCodelensCommands(), 1)
		assert.Len(t, fakeIssues[0].GetCodeActions(), 1)
	})
}

func Test_ideSnykURI(t *testing.T) {
	testutil.UnitTest(t)
	t.Run("generates correct URI", func(t *testing.T) {
		issue, _ := setupTestData(t)
		actualURI, err := SnykMagnetUri(util.Ptr(zerolog.Nop()), issue, ShowInDetailPanelIdeCommand)
		assert.NoError(t, err)
		assertTestDataSnykURI(t, actualURI)
	})

	t.Run("handles missing Key in additional data", func(t *testing.T) {
		affectedFilePath := filepath.Join(t.TempDir(), testFixtureSubDir, testFixtureFile)
		issue := &snyk.Issue{
			ID:               "vuln-id",
			AffectedFilePath: types.FilePath(affectedFilePath),
			Product:          product.ProductCode,
			AdditionalData:   snyk.CodeIssueData{Key: ""}, // falls back to issue.ID via IssueId()
		}

		actualURI, err := SnykMagnetUri(util.Ptr(zerolog.Nop()), issue, ShowInDetailPanelIdeCommand)
		assert.NoError(t, err)
		assertSnykURIMatches(t, actualURI, testFixturePathSuffix, url.Values{
			"action":  {ShowInDetailPanelIdeCommand},
			"issueId": {"vuln-id"},
			"product": {"Snyk Code"},
		})
	})

	// lspUri.File's file:// shape puts a leading '/' before the drive letter (RFC 8089),
	// keeping the authority empty; a raw path in url.URL instead renders "C:%5Cpath" and
	// "C:" parses as host:port (RFC 3986).
	t.Run("Windows paths follow RFCs for encoding", func(t *testing.T) {
		filePath := `C:\Mac\Home\Documents\Code\JavaScript\snyk-goof\db.js`
		issue := &snyk.Issue{
			AffectedFilePath: types.FilePath(filePath),
			Product:          product.ProductCode,
			AdditionalData:   snyk.CodeIssueData{Key: testFixtureIssueId},
		}

		actualURI, err := SnykMagnetUri(util.Ptr(zerolog.Nop()), issue, ShowInDetailPanelIdeCommand)
		require.NoError(t, err)

		parsed, parseErr := url.Parse(actualURI)
		require.NoError(t, parseErr, "generated URI should be re-parseable, but got: %s", actualURI)
		assert.Empty(t, parsed.Host, "authority should be empty, not swallow the Windows drive letter as a host")
		assert.True(t, strings.HasPrefix(parsed.Path, "/C:"), "path should start with a leading slash before the drive letter, got: %s", parsed.Path)
	})
}

func TestIssueId(t *testing.T) {
	testutil.UnitTest(t)
	testCases := []struct {
		name     string
		issue    *snyk.Issue
		expected string
	}{
		{
			name: "Nil AdditionalData",
			issue: &snyk.Issue{
				ID:             "vuln-id",
				AdditionalData: nil,
			},
			expected: "vuln-id",
		},
		{
			name: "CodeIssueData with empty key",
			issue: &snyk.Issue{
				ID: "vuln-id",
				AdditionalData: snyk.CodeIssueData{
					Key: "",
				},
			},
			expected: "vuln-id",
		},
		{
			name: "CodeIssueData with key",
			issue: &snyk.Issue{
				ID: "vuln-id",
				AdditionalData: snyk.CodeIssueData{
					Key: "code-issue-key",
				},
			},
			expected: "code-issue-key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IssueId(tc.issue)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}
