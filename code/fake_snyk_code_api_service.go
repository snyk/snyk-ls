package code

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
	"github.com/snyk/snyk-ls/lsp"
)

const (
	CreateBundleWithSourceOperation = "createBundleWithSource"
	ExtendBundleWithSourceOperation = "extendBundleWithSource"
	RunAnalysisOperation            = "runAnalysis"
	GetFiltersOperation             = "getFilters"
)

var (
	mutex             = &sync.Mutex{}
	fakeDiagnosticUri sglsp.DocumentURI

	fakeRange = sglsp.Range{
		Start: sglsp.Position{
			Line:      0,
			Character: 3,
		},
		End: sglsp.Position{
			Line:      0,
			Character: 7,
		},
	}
	FakeHover = lsp.HoverDetails{
		Id:      "12",
		Range:   fakeRange,
		Message: "You have been hacked!",
	}
	FakeDiagnostic = lsp.Diagnostic{
		Range:    fakeRange,
		Severity: sglsp.Error,
		Code:     "SNYK-123",
		Source:   "snyk code",
		Message:  "This is a dummy error (severity error)",
		// CodeDescription: lsp.CodeDescription{Href: "https://snyk.io"},
	}
	FakeFilters = []string{".cjs", ".ejs", ".es", ".es6", ".htm", ".html", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue", ".java", ".erb", ".haml", ".rb", ".rhtml", ".slim", ".kt", ".swift", ".cls", ".config", ".pom", ".wxs", ".xml", ".xsd", ".aspx", ".cs", ".py", ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".php", ".phtml"}
)

func FakeDiagnosticUri() (documentURI sglsp.DocumentURI, path string) {
	temp, err := os.MkdirTemp(os.TempDir(), "fakeDiagnosticTempDir")
	if err != nil {
		log.Fatal().Err(err).Msg("couldn't create tempdir")
	}
	filePath := temp + string(os.PathSeparator) + "Dummy.java"
	classWithQualityIssue := "public class AnnotatorTest {\n  public static void delay(long millis) {\n    try {\n      Thread.sleep(millis);\n    } catch (InterruptedException e) {\n      e.printStackTrace();\n    }\n  }\n};"
	err = os.WriteFile(filePath, []byte(classWithQualityIssue), 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create fake diagnostic file for Snyk Code Fake Service")
	}
	documentURI = uri.PathToUri(filePath)
	fakeDiagnosticUri = documentURI
	return documentURI, temp
}

type FakeSnykCodeClient struct {
	Calls               map[string][][]interface{}
	HasCreatedNewBundle bool
	HasExtendedBundle   bool
	TotalBundleCount    int
	ExtendedBundleCount int
}

func (f *FakeSnykCodeClient) addCall(params []interface{}, op string) {
	mutex.Lock()
	defer mutex.Unlock()
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
	mutex.Lock()
	defer mutex.Unlock()
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
	f.ExtendedBundleCount = 0
	f.TotalBundleCount = 0
	f.HasExtendedBundle = false
	f.HasExtendedBundle = false
}

func (f *FakeSnykCodeClient) GetAllCalls(op string) [][]interface{} {
	mutex.Lock()
	defer mutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	return calls
}

func (f *FakeSnykCodeClient) GetFilters(_ context.Context, requestId string) (configFiles []string, extensions []string, err error) {
	params := []interface{}{configFiles, extensions, err}
	f.addCall(params, GetFiltersOperation)
	return make([]string, 0), FakeFilters, nil
}

func (f *FakeSnykCodeClient) CreateBundle(_ context.Context, files map[sglsp.DocumentURI]BundleFile, requestId string) (string, []sglsp.DocumentURI, error) {
	f.TotalBundleCount++
	f.HasCreatedNewBundle = true
	params := []interface{}{files}
	f.addCall(params, CreateBundleWithSourceOperation)
	return util.Hash([]byte(fmt.Sprint(rand.Int()))), nil, nil
}

func (f *FakeSnykCodeClient) ExtendBundle(
	_ context.Context,
	bundleHash string,
	files map[sglsp.DocumentURI]BundleFile,
	removedFiles []sglsp.DocumentURI,
	requestId string,
) (string, []sglsp.DocumentURI, error) {
	f.HasExtendedBundle = true
	f.TotalBundleCount++
	f.ExtendedBundleCount++
	params := []interface{}{bundleHash, files, removedFiles}
	f.addCall(params, ExtendBundleWithSourceOperation)
	return util.Hash([]byte(fmt.Sprint(rand.Int()))), nil, nil
}

func (f *FakeSnykCodeClient) RunAnalysis(
	_ context.Context,
	bundleHash string,
	_ string,
	limitToFiles []sglsp.DocumentURI,
	severity int,
	requestId string,
) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]lsp.HoverDetails, AnalysisStatus, error) {
	params := []interface{}{bundleHash, limitToFiles, severity}
	f.addCall(params, RunAnalysisOperation)

	diagnosticMap := map[sglsp.DocumentURI][]lsp.Diagnostic{}
	hoverMap := map[sglsp.DocumentURI][]lsp.HoverDetails{}

	var diagnostics []lsp.Diagnostic
	var hovers []lsp.HoverDetails

	diagnosticMap[fakeDiagnosticUri] = append(diagnostics, FakeDiagnostic)
	hoverMap[fakeDiagnosticUri] = append(hovers, FakeHover)

	log.Trace().Str("method", "RunAnalysis").Str("bundleHash", bundleHash).Interface("fakeDiagnostic", FakeDiagnostic).Msg("fake backend call received & answered")
	return diagnosticMap, hoverMap, AnalysisStatus{message: "COMPLETE", percentage: 100}, nil
}
