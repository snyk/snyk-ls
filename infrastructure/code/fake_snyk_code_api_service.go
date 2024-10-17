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
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
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

	fakeRange = snyk.Range{
		Start: snyk.Position{
			Line:      0,
			Character: 3,
		},
		End: snyk.Position{
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

	FakeIssue = snyk.Issue{
		ID:               "SNYK-123",
		Range:            fakeRange,
		Severity:         snyk.High,
		Product:          product.ProductCode,
		IssueType:        snyk.CodeQualityIssue,
		Message:          "This is a dummy error (severity error)",
		CodelensCommands: []types.CommandData{FakeCommand, FakeFixCommand},
		CodeActions:      []snyk.CodeAction{FakeCodeAction},
		AdditionalData: snyk.CodeIssueData{
			Key:           uuid.New().String(),
			IsAutofixable: true,
		},
	}

	FakeCodeAction = snyk.CodeAction{
		Title:   "FakeAction",
		Command: &FakeCommand,
	}

	FakeFilters = []string{".cjs", ".ejs", ".es", ".es6", ".htm", ".html", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue", ".java", ".erb", ".haml", ".rb", ".rhtml", ".slim", ".kt", ".swift", ".cls", ".config", ".pom", ".wxs", ".xml", ".xsd", ".aspx", ".cs", ".py", ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".php", ".phtml"}
)

func TempWorkdirWithIssues(t *testing.T) (filePath string, folderPath string) {
	t.Helper()
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()

	folderPath = t.TempDir()

	command := exec.Command("git", "init")
	command.Dir = folderPath
	_, err := command.Output()
	require.NoError(t, err)

	command = exec.Command("git", "remote", "add", "origin", "https://dummy.dummy.io/gitty.git")
	command.Dir = folderPath
	_, err = command.Output()
	require.NoError(t, err)

	filePath = filepath.Join(folderPath, "Dummy"+FakeFileExtension)
	classWithQualityIssue := "public class AnnotatorTest {\n  public static void delay(long millis) {\n    try {\n      Thread.sleep(millis);\n    } catch (InterruptedException e) {\n      e.printStackTrace();\n    }\n  }\n};"
	err = os.WriteFile(filePath, []byte(classWithQualityIssue), 0600)
	if err != nil {
		t.Fatal(err, "couldn't create temp file for fake diagnostic")
	}
	FakeIssue.AffectedFilePath = filePath
	return
}

type FakeSnykCodeClient struct {
	Calls                  map[string][][]any
	HasCreatedNewBundle    bool
	HasExtendedBundle      bool
	ExtendBundleFiles      map[string]BundleFile
	TotalBundleCount       int
	ExtendedBundleCount    int
	AnalysisDuration       time.Duration
	FailOnCreateBundle     bool
	ConfigFiles            []string
	currentConcurrentScans int
	maxConcurrentScans     int
	NoFixSuggestions       bool
	UnifiedDiffSuggestions []AutofixUnifiedDiffSuggestion
	AutofixStatus          AutofixStatus
	Options                map[string]AnalysisOptions
	C                      *config.Config
}

func (f *FakeSnykCodeClient) GetAutofixDiffs(_ context.Context, _ string, _ AutofixOptions) (unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion, status AutofixStatus, err error) {
	f.AutofixStatus = AutofixStatus{message: completeStatus }
	return f.UnifiedDiffSuggestions, f.AutofixStatus, nil
}


func (f *FakeSnykCodeClient) GetAutofixResponse(_ context.Context, _ string, _ AutofixOptions) (autofixResponse AutofixResponse, status AutofixStatus, err error) {
	f.AutofixStatus = AutofixStatus{message: completeStatus }
	return autofixResponse, f.AutofixStatus, nil
}

func (f *FakeSnykCodeClient) addCall(params []any, op string) {
	if f.Calls == nil {
		f.Calls = make(map[string][][]any)
	}
	calls := f.Calls[op]
	var opParams []any
	opParams = append(opParams, params...)
	f.Calls[op] = append(calls, opParams)
}

func (f *FakeSnykCodeClient) GetCallParams(callNo int, op string) []any {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	params := calls[callNo]
	if params == nil {
		return nil
	}
	return params
}

func (f *FakeSnykCodeClient) Clear() {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()
	f.ExtendedBundleCount = 0
	f.TotalBundleCount = 0
	f.HasExtendedBundle = false
}

func (f *FakeSnykCodeClient) GetAllCalls(op string) [][]any {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	return calls
}

func (f *FakeSnykCodeClient) GetFilters(_ context.Context) (
	filters FiltersResponse,
	err error,
) {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()
	params := []any{filters.ConfigFiles,
		filters.Extensions,
		err}
	f.addCall(params, GetFiltersOperation)
	return FiltersResponse{ConfigFiles: f.ConfigFiles,
		Extensions: FakeFilters,
	}, nil
}

func (f *FakeSnykCodeClient) CreateBundle(_ context.Context,
	files map[string]string,
) (bundleHash string, missingFiles []string, err error) {
	if f.FailOnCreateBundle {
		return "", nil, errors.New("Mock Code client failed intentionally on CreateBundle")
	}

	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()
	f.TotalBundleCount++
	f.HasCreatedNewBundle = true
	params := []any{files}
	f.addCall(params, CreateBundleOperation)
	for filePath := range files {
		missingFiles = append(missingFiles, filePath)
	}
	return util.Hash([]byte(fmt.Sprint(rand.Int()))), missingFiles, nil
}

func (f *FakeSnykCodeClient) ExtendBundle(
	_ context.Context,
	bundleHash string,
	files map[string]BundleFile,
	removedFiles []string,
) (string, []string, error) {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()
	f.HasExtendedBundle = true
	f.TotalBundleCount++
	f.ExtendedBundleCount++
	f.ExtendBundleFiles = files
	params := []any{bundleHash, files, removedFiles}
	f.addCall(params, ExtendBundleWithSourceOperation)
	return util.Hash([]byte(fmt.Sprint(rand.Int()))), nil, nil
}

var successfulResult = AnalysisStatus{
	message:    "COMPLETE",
	percentage: 100,
}

func (f *FakeSnykCodeClient) RunAnalysis(
	_ context.Context,
	options AnalysisOptions,
	_ string,
) ([]snyk.Issue, AnalysisStatus, error) {
	FakeSnykCodeApiServiceMutex.Lock()
	f.currentConcurrentScans++
	if f.currentConcurrentScans > f.maxConcurrentScans {
		f.maxConcurrentScans = f.currentConcurrentScans
	}
	if f.Options == nil {
		f.Options = make(map[string]AnalysisOptions)
	}
	FakeSnykCodeApiServiceMutex.Unlock()
	<-time.After(f.AnalysisDuration)

	FakeSnykCodeApiServiceMutex.Lock()
	f.currentConcurrentScans--
	params := []any{options.bundleHash, options.limitToFiles, options.severity}
	f.addCall(params, RunAnalysisOperation)
	FakeSnykCodeApiServiceMutex.Unlock()

	FakeSnykCodeApiServiceMutex.Lock()
	issues := []snyk.Issue{FakeIssue}
	if f.NoFixSuggestions {
		if issueData, ok := issues[0].AdditionalData.(snyk.CodeIssueData); ok {
			issueData.IsAutofixable = false
			issues[0].AdditionalData = issueData
		}
	}
	f.Options[options.bundleHash] = options
	FakeSnykCodeApiServiceMutex.Unlock()

	f.C.Logger().Trace().Str("method", "RunAnalysis").Interface(
		"fakeDiagnostic",
		FakeIssue,
	).Msg("fake backend call received & answered")
	return issues, successfulResult, nil
}

func (f *FakeSnykCodeClient) GetAutofixSuggestions(
	_ context.Context,
	options AutofixOptions,
	_ string,
) ([]AutofixSuggestion, AutofixStatus, error) {
	<-time.After(f.AnalysisDuration)
	FakeSnykCodeApiServiceMutex.Lock()
	params := []any{options.bundleHash, options.filePath, options.issue.ID, options.issue.Range.Start.Line}
	f.addCall(params, RunAutofixOperation)
	FakeSnykCodeApiServiceMutex.Unlock()

	if f.NoFixSuggestions {
		f.C.Logger().Trace().Str("method", "GetAutofixSuggestions").Interface("fakeAutofix",
			"someAutofixSuggestion").Msg("fake backend call received & answered with no suggestions")
		return nil, AutofixStatus{message: "COMPLETE"}, nil
	}

	suggestions := []AutofixSuggestion{
		// First suggestion
		{
			FixId: "123e4567-e89b-12d3-a456-426614174000/1",
			AutofixEdit: snyk.WorkspaceEdit{
				Changes: map[string][]snyk.TextEdit{
					options.filePath: {snyk.TextEdit{
						FullText: FakeAutofixSuggestionNewText,
						Range: snyk.Range{
							Start: snyk.Position{Line: 0, Character: 0},
							End:   snyk.Position{Line: 10000, Character: 0},
						},
						NewText: FakeAutofixSuggestionNewText,
					}},
				},
			},
		},
		// Second suggestion -- currently dropped
		{
			FixId: "123e4567-e89b-12d3-a456-426614174000/2",
			AutofixEdit: snyk.WorkspaceEdit{
				Changes: map[string][]snyk.TextEdit{
					options.filePath: {snyk.TextEdit{
						FullText: "FAKE_AUTOFIX_UNUSED",
						Range: snyk.Range{
							Start: snyk.Position{Line: 0, Character: 0},
							End:   snyk.Position{Line: 10000, Character: 0},
						},
						NewText: "FAKE_AUTOFIX_UNUSED",
					}},
				},
			},
		},
	}

	f.C.Logger().Trace().Str("method", "GetAutofixSuggestions").Interface("fakeAutofix",
		"someAutofixSuggestion").Msg("fake backend call received & answered")
	return suggestions, AutofixStatus{message: "COMPLETE"}, nil
}

func (f *FakeSnykCodeClient) SubmitAutofixFeedback(_ context.Context, _ string, _ string) error {
	return nil
}
