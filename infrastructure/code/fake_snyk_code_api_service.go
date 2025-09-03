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
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	CreateBundleOperation           = "createBundle"
	ExtendBundleWithSourceOperation = "extendBundleWithSource"
	RunAnalysisOperation            = "runAnalysis"
	RunAutofixOperation             = "runAutofix"
	GetFiltersOperation             = "getFilters"
	FakeFileExtension               = ".java"
	// Helper constants to synchronize fake results and tests
	FakeAutofixSuggestionNewText = "FAKE_AUTOFIX_NEW_TEXT"
)

var (
	FakeSnykCodeApiServiceMutex = &sync.Mutex{}

	fakeRange = types.Range{
		Start: types.Position{
			Line:      0,
			Character: 3,
		},
		End: types.Position{
			Line:      0,
			Character: 7,
		},
	}
	FakeCommand = types.CommandData{
		Title:     "Code Flow blah blah fake",
		CommandId: types.NavigateToRangeCommand,
		Arguments: []any{"path", fakeRange},
	}
	FakeFixCommand = types.CommandData{
		Title:     "Code Flow blah blah fake",
		CommandId: types.CodeFixCommand,
		Arguments: []any{"id", "path", fakeRange},
	}

	FakeIssue = &snyk.Issue{
		ID:               "SNYK-123",
		Range:            fakeRange,
		Severity:         types.High,
		Product:          product.ProductCode,
		IssueType:        types.CodeSecurityVulnerability,
		Message:          "This is a dummy error (severity error)",
		CodelensCommands: []types.CommandData{FakeCommand, FakeFixCommand},
		CodeActions:      []types.CodeAction{&FakeCodeAction},
		AdditionalData: snyk.CodeIssueData{
			Key:           uuid.New().String(),
			IsAutofixable: true,
		},
	}

	FakeCodeAction = snyk.CodeAction{
		Title:   "FakeAction",
		Command: &FakeCommand,
	}
)

func TempWorkdirWithIssues(t *testing.T) (types.FilePath, types.FilePath) {
	t.Helper()
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()

	folderPath := t.TempDir()

	command := exec.Command("git", "init")
	command.Dir = folderPath
	_, err := command.Output()
	require.NoError(t, err)

	command = exec.Command("git", "remote", "add", "origin", "https://dummy.dummy.io/gitty.git")
	command.Dir = folderPath
	_, err = command.Output()
	require.NoError(t, err)

	filePath := filepath.Join(folderPath, "Dummy"+FakeFileExtension)
	classWithSQLInjection := "import java.sql.Connection;\nimport java.sql.DriverManager;\nimport java.sql.ResultSet;\nimport java.sql.SQLException;\nimport java.sql.Statement;\n\npublic class AnnotatorTest {\n  public static void main(String[] args) {\n    try {\n      Class.forName(\"com.mysql.cj.jdbc.Driver\");\n      Connection conn = DriverManager.getConnection(\n          \"jdbc:mysql://localhost:3306/mydb\", \"root\", \"password\");\n      Statement stmt = conn.createStatement();\n      String query = \"SELECT * FROM users WHERE name = '\" + args[0] + \"'\";\n      ResultSet rs = stmt.executeQuery(query);\n      while (rs.next()) {\n        System.out.println(rs.getString(1));\n      }\n      conn.close();\n    } catch (ClassNotFoundException e) {\n      e.printStackTrace();\n    } catch (SQLException e) {\n      e.printStackTrace();\n    }\n  }\n};"
	err = os.WriteFile(filePath, []byte(classWithSQLInjection), 0600)
	if err != nil {
		t.Fatal(err, "couldn't create temp file for fake diagnostic")
	}
	FakeIssue.AffectedFilePath = types.FilePath(filePath)
	return types.FilePath(filePath), types.FilePath(folderPath)
}
