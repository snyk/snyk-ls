package code

import (
	"fmt"
	"math/rand"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/util"
)

var (
	FakeDiagnosticUri = sglsp.DocumentURI("file://testdata/Dummy.java")
	FakeDiagnostic    = lsp.Diagnostic{
		Range: sglsp.Range{
			Start: sglsp.Position{
				Line:      0,
				Character: 3,
			},
			End: sglsp.Position{
				Line:      0,
				Character: 7,
			},
		},
		Severity: sglsp.Error,
		Code:     "SNYK-123",
		Source:   "snyk code",
		Message:  "This is a dummy error (severity error)",
		// CodeDescription: lsp.CodeDescription{Href: "https://snyk.io"},
	}
	FakeCodeLens = sglsp.CodeLens{
		Range: sglsp.Range{
			Start: sglsp.Position{
				Line:      0,
				Character: 5,
			},
			End: sglsp.Position{
				Line:      3,
				Character: 80,
			},
		},
		Command: sglsp.Command{
			Title:     "Fake Lens Title",
			Command:   "Fake Lens Command",
			Arguments: []interface{}{"FakeArgs"},
		},
	}
)

const (
	CreateBundleWithSourceOperation = "createBundleWithSource"
	ExtendBundleWithSourceOperation = "extendBundleWithSource"
	RunAnalysisOperation            = "runAnalysis"
)

type FakeSnykCodeApiService struct {
	Calls map[string][][]interface{}
}

func (f *FakeSnykCodeApiService) addCall(params []interface{}, op string) {
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
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	return calls
}

func (f *FakeSnykCodeApiService) CreateBundle(files map[sglsp.DocumentURI]File) (string, []sglsp.DocumentURI, error) {
	params := []interface{}{files}
	f.addCall(params, CreateBundleWithSourceOperation)
	BundleHash := util.Hash([]byte(fmt.Sprint(rand.Int())))

	return BundleHash, nil, nil
}

func (f *FakeSnykCodeApiService) ExtendBundle(bundleHash string, files map[sglsp.DocumentURI]File, removedFiles []sglsp.DocumentURI) (string, []sglsp.DocumentURI, error) {
	params := []interface{}{bundleHash, files, removedFiles}
	f.addCall(params, ExtendBundleWithSourceOperation)
	return bundleHash, nil, nil
}
func (f *FakeSnykCodeApiService) RunAnalysis(bundleHash string, shardKey string, limitToFiles []sglsp.DocumentURI, severity int) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]sglsp.CodeLens, string, error) {
	params := []interface{}{bundleHash, limitToFiles, severity}
	f.addCall(params, RunAnalysisOperation)

	diagnosticMap := map[sglsp.DocumentURI][]lsp.Diagnostic{}
	var diagnostics []lsp.Diagnostic
	diagnosticMap[FakeDiagnosticUri] = append(diagnostics, FakeDiagnostic)

	codeLensMap := map[sglsp.DocumentURI][]sglsp.CodeLens{}
	var codeLenses []sglsp.CodeLens
	codeLensMap[FakeDiagnosticUri] = append(codeLenses, FakeCodeLens)

	log.Trace().Str("method", "RunAnalysis").Str("bundleHash", bundleHash).Interface("fakeDiagnostic", FakeDiagnostic).Msg("fake backend call received & answered")
	return diagnosticMap, codeLensMap, "COMPLETE", nil
}
