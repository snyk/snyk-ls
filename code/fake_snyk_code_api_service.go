package code

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/util"
)

const (
	CreateBundleWithSourceOperation = "createBundleWithSource"
	ExtendBundleWithSourceOperation = "extendBundleWithSource"
	RunAnalysisOperation            = "runAnalysis"
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
)

func FakeDiagnosticUri() (documentURI sglsp.DocumentURI, path string) {
	temp, err := os.MkdirTemp(os.TempDir(), "fakeDiagnosticTempDir")
	if err != nil {
		logger.WithError(err).Error(context.Background(), "couldn't create temp dir")
	}
	filePath := temp + string(os.PathSeparator) + "Dummy.java"
	classWithQualityIssue := "public class AnnotatorTest {\n  public static void delay(long millis) {\n    try {\n      Thread.sleep(millis);\n    } catch (InterruptedException e) {\n      e.printStackTrace();\n    }\n  }\n};"
	err = os.WriteFile(filePath, []byte(classWithQualityIssue), 0600)
	if err != nil {
		logger.WithError(err).Error(context.Background(), "couldn't create fake diagnostic file")
	}
	documentURI = uri.PathToUri(filePath)
	fakeDiagnosticUri = documentURI
	return documentURI, temp
}

type FakeSnykCodeApiService struct {
	Calls map[string][][]interface{}
}

func (f *FakeSnykCodeApiService) addCall(params []interface{}, op string) {
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

func (f *FakeSnykCodeApiService) GetCallParams(callNo int, op string) []interface{} {
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

func (f *FakeSnykCodeApiService) GetAllCalls(op string) [][]interface{} {
	mutex.Lock()
	defer mutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	return calls
}

func (f *FakeSnykCodeApiService) CreateBundle(_ context.Context, files map[sglsp.DocumentURI]File) (string, []sglsp.DocumentURI, error) {
	params := []interface{}{files}
	f.addCall(params, CreateBundleWithSourceOperation)
	BundleHash := util.Hash([]byte(fmt.Sprint(rand.Int())))

	return BundleHash, nil, nil
}

func (f *FakeSnykCodeApiService) ExtendBundle(
	_ context.Context,
	bundleHash string,
	files map[sglsp.DocumentURI]File,
	removedFiles []sglsp.DocumentURI,
) (string, []sglsp.DocumentURI, error) {
	params := []interface{}{bundleHash, files, removedFiles}
	f.addCall(params, ExtendBundleWithSourceOperation)
	return bundleHash, nil, nil
}

func (f *FakeSnykCodeApiService) RunAnalysis(
	ctx context.Context,
	bundleHash string,
	_ string,
	limitToFiles []sglsp.DocumentURI,
	severity int,
) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]lsp.HoverDetails, string, error) {
	params := []interface{}{bundleHash, limitToFiles, severity}
	f.addCall(params, RunAnalysisOperation)

	diagnosticMap := map[sglsp.DocumentURI][]lsp.Diagnostic{}
	hoverMap := map[sglsp.DocumentURI][]lsp.HoverDetails{}

	var diagnostics []lsp.Diagnostic
	var hovers []lsp.HoverDetails

	diagnosticMap[fakeDiagnosticUri] = append(diagnostics, FakeDiagnostic)
	hoverMap[fakeDiagnosticUri] = append(hovers, FakeHover)

	logger.
		WithField("method", "RunAnalysis").
		WithField("bundleHash", bundleHash).
		WithField("fakeDiagnostic", FakeDiagnostic).
		Trace(ctx, "fake backend call received & answered")
	return diagnosticMap, hoverMap, "COMPLETE", nil
}
