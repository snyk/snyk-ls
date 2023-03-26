/*
 * © 2022 Snyk Limited All rights reserved.
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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	CreateBundleOperation           = "createBundle"
	ExtendBundleWithSourceOperation = "extendBundleWithSource"
	RunAnalysisOperation            = "runAnalysis"
	RunAutofixOperation             = "runAutofix"
	GetFiltersOperation             = "getFilters"

	// Helper constants to synchronize fake results and tests
	FakeAutofixFileUri           = "/some/path/uri"
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
	FakeCommand = snyk.Command{
		Title:     "Code Flow blah blah fake",
		CommandId: snyk.NavigateToRangeCommand,
		Arguments: []any{"path", fakeRange},
	}

	FakeIssue = snyk.Issue{
		ID:          "SNYK-123",
		Range:       fakeRange,
		Severity:    snyk.High,
		Product:     product.ProductCode,
		IssueType:   snyk.CodeQualityIssue,
		Message:     "This is a dummy error (severity error)",
		Commands:    []snyk.Command{FakeCommand},
		CodeActions: []snyk.CodeAction{FakeCodeAction},
	}

	FakeCodeAction = snyk.CodeAction{
		Title:   "FakeAction",
		Command: &FakeCommand,
	}

	FakeFilters = []string{".cjs", ".ejs", ".es", ".es6", ".htm", ".html", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue", ".java", ".erb", ".haml", ".rb", ".rhtml", ".slim", ".kt", ".swift", ".cls", ".config", ".pom", ".wxs", ".xml", ".xsd", ".aspx", ".cs", ".py", ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".php", ".phtml"}
)

func TempWorkdirWithVulnerabilities(t *testing.T) (filePath string, path string) {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()

	temp := t.TempDir()
	temp = filepath.Clean(temp)
	temp, err := filepath.Abs(temp)
	if err != nil {
		t.Fatal(err, "couldn't get abs path of tempdir")
	}

	filePath = filepath.Join(temp, "Dummy.java")
	classWithQualityIssue := "public class AnnotatorTest {\n  public static void delay(long millis) {\n    try {\n      Thread.sleep(millis);\n    } catch (InterruptedException e) {\n      e.printStackTrace();\n    }\n  }\n};"
	err = os.WriteFile(filePath, []byte(classWithQualityIssue), 0600)
	if err != nil {
		t.Fatal(err, "couldn't create temp file for fake diagnostic")
	}
	FakeIssue.AffectedFilePath = filePath
	return filePath, temp
}

type FakeSnykCodeClient struct {
	Calls                        map[string][][]any
	HasCreatedNewBundle          bool
	HasExtendedBundle            bool
	TotalBundleCount             int
	ExtendedBundleCount          int
	AnalysisDuration             time.Duration
	FailOnCreateBundle           bool
	ConfigFiles                  []string
	currentConcurrentScans       int
	maxConcurrentScans           int
	AutofixDuration              time.Duration
	currentConcurrentAutofixRuns int
	maxConcurrentAutofixRuns     int
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

func (f *FakeSnykCodeClient) GetFilters(_ context.Context) (configFiles []string, extensions []string, err error) {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()
	params := []any{configFiles, extensions, err}
	f.addCall(params, GetFiltersOperation)
	return f.ConfigFiles, FakeFilters, nil
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
) ([]snyk.Issue, AnalysisStatus, error) {

	FakeSnykCodeApiServiceMutex.Lock()
	f.currentConcurrentScans++
	if f.currentConcurrentScans > f.maxConcurrentScans {
		f.maxConcurrentScans = f.currentConcurrentScans
	}
	FakeSnykCodeApiServiceMutex.Unlock()
	<-time.After(f.AnalysisDuration)
	FakeSnykCodeApiServiceMutex.Lock()
	f.currentConcurrentScans--
	params := []any{options.bundleHash, options.limitToFiles, options.severity}
	f.addCall(params, RunAnalysisOperation)
	FakeSnykCodeApiServiceMutex.Unlock()

	issues := []snyk.Issue{FakeIssue}

	log.Trace().Str("method", "RunAnalysis").Interface(
		"fakeDiagnostic",
		FakeIssue,
	).Msg("fake backend call received & answered")
	return issues, successfulResult, nil
}

func (f *FakeSnykCodeClient) RunAutofix(
	_ context.Context,
	options AutofixOptions,
) ([]AutofixSuggestion, AutofixStatus, error) {
	FakeSnykCodeApiServiceMutex.Lock()
	f.currentConcurrentAutofixRuns++
	if f.currentConcurrentAutofixRuns > f.maxConcurrentAutofixRuns {
		f.maxConcurrentAutofixRuns = f.currentConcurrentAutofixRuns
	}
	FakeSnykCodeApiServiceMutex.Unlock()
	<-time.After(f.AnalysisDuration)
	FakeSnykCodeApiServiceMutex.Lock()
	f.currentConcurrentAutofixRuns--
	params := []any{options.bundleHash, options.filePath, options.issue.ID, options.issue.Range.Start.Line}
	f.addCall(params, RunAutofixOperation)
	FakeSnykCodeApiServiceMutex.Unlock()

	suggestions := []AutofixSuggestion{
		// First suggestion
		{
			AutofixEdit: snyk.WorkspaceEdit{
				Changes: map[string][]snyk.TextEdit{
					FakeAutofixFileUri: {snyk.TextEdit{
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
			AutofixEdit: snyk.WorkspaceEdit{
				Changes: map[string][]snyk.TextEdit{
					FakeAutofixFileUri: {snyk.TextEdit{
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

	log.Trace().Str("method", "RunAutofix").Interface("fakeAutofix", "someAutofixSuggestion").Msg("fake backend call received & answered")
	return suggestions, AutofixStatus{message: "COMPLETE"}, nil
}
