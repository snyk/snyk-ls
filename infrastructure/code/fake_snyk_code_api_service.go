package code

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	CreateBundleOperation           = "createBundle"
	ExtendBundleWithSourceOperation = "extendBundleWithSource"
	RunAnalysisOperation            = "runAnalysis"
	GetFiltersOperation             = "getFilters"
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
	FakeIssue = snyk.Issue{
		ID:       "SNYK-123",
		Range:    fakeRange,
		Severity: snyk.High,
		Message:  "This is a dummy error (severity error)",
	}
	FakeFilters = []string{".cjs", ".ejs", ".es", ".es6", ".htm", ".html", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue", ".java", ".erb", ".haml", ".rb", ".rhtml", ".slim", ".kt", ".swift", ".cls", ".config", ".pom", ".wxs", ".xml", ".xsd", ".aspx", ".cs", ".py", ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".php", ".phtml"}
)

func FakeDiagnosticUri() (filePath string, path string) {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()

	temp, err := os.MkdirTemp(os.TempDir(), "fakeDiagnosticTempDir")
	if err != nil {
		log.Fatal().Err(err).Msg("couldn't create tempdir")
	}
	filePath = temp + string(os.PathSeparator) + "Dummy.java"
	classWithQualityIssue := "public class AnnotatorTest {\n  public static void delay(long millis) {\n    try {\n      Thread.sleep(millis);\n    } catch (InterruptedException e) {\n      e.printStackTrace();\n    }\n  }\n};"
	err = os.WriteFile(filePath, []byte(classWithQualityIssue), 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create fake diagnostic file for Snyk Code Fake Service")
	}
	FakeIssue.AffectedFilePath = filePath
	return filePath, temp
}

type FakeSnykCodeClient struct {
	Calls               map[string][][]interface{}
	HasCreatedNewBundle bool
	HasExtendedBundle   bool
	TotalBundleCount    int
	ExtendedBundleCount int
}

func (f *FakeSnykCodeClient) addCall(params []interface{}, op string) {
	if f.Calls == nil {
		f.Calls = make(map[string][][]interface{})
	}
	calls := f.Calls[op]
	var opParams []interface{}
	for p := range params {
		opParams = append(opParams, params[p])
	}
	f.Calls[op] = append(calls, opParams)
}

func (f *FakeSnykCodeClient) GetCallParams(callNo int, op string) []interface{} {
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

func (f *FakeSnykCodeClient) GetAllCalls(op string) [][]interface{} {
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
	params := []interface{}{configFiles, extensions, err}
	f.addCall(params, GetFiltersOperation)
	return make([]string, 0), FakeFilters, nil
}

func (f *FakeSnykCodeClient) CreateBundle(_ context.Context, files map[string]string) (bundleHash string, missingFiles []string, err error) {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()
	f.TotalBundleCount++
	f.HasCreatedNewBundle = true
	params := []interface{}{files}
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
	params := []interface{}{bundleHash, files, removedFiles}
	f.addCall(params, ExtendBundleWithSourceOperation)
	return util.Hash([]byte(fmt.Sprint(rand.Int()))), nil, nil
}

func (f *FakeSnykCodeClient) RunAnalysis(
	_ context.Context,
	options AnalysisOptions,
) ([]snyk.Issue, AnalysisStatus, error) {
	FakeSnykCodeApiServiceMutex.Lock()
	defer FakeSnykCodeApiServiceMutex.Unlock()
	params := []interface{}{options.bundleHash, options.limitToFiles, options.severity}
	f.addCall(params, RunAnalysisOperation)

	issues := []snyk.Issue{FakeIssue}

	log.Trace().Str("method", "RunAnalysis").Interface("fakeDiagnostic", FakeIssue).Msg("fake backend call received & answered")
	return issues, AnalysisStatus{message: "COMPLETE", percentage: 100}, nil
}
