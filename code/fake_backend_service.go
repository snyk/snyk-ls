package code

import (
	"github.com/google/uuid"
	"github.com/snyk/snyk-lsp/util"
	"github.com/sourcegraph/go-lsp"
)

var (
	FakeDiagnosticUri = lsp.DocumentURI("file:///Users/bdoetsch/workspace/infrastructure-as-code-goof/Dummy.java")
	FakeDiagnostic    = lsp.Diagnostic{
		Range: lsp.Range{
			Start: lsp.Position{
				Line:      0,
				Character: 3,
			},
			End: lsp.Position{
				Line:      0,
				Character: 7,
			},
		},
		Severity: lsp.Error,
		Code:     "SNYK-123",
		Source:   "snyk code",
		Message:  "This is a dummy error (severity error)",
	}
)

const (
	CreateBundleWithSourceOperation = "createBundleWithSource"
	ExtendBundleWithSourceOperation = "extendBundleWithSource"
	RetrieveDiagnosticsOperation    = "extendBundleWithSource"
)

type FakeBackendService struct {
	BundleHash string
	Calls      map[string][][]interface{}
}

func (f *FakeBackendService) addCall(params []interface{}, op string) {
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

func (f *FakeBackendService) GetCallParams(callNo int, op string) []interface{} {
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

func (f *FakeBackendService) CreateBundle(files map[lsp.DocumentURI]File) (string, []lsp.DocumentURI, error) {
	params := []interface{}{files}
	f.addCall(params, CreateBundleWithSourceOperation)
	if f.BundleHash == "" {
		// create a random hash
		f.BundleHash = util.Hash(uuid.NewString())
	}
	return f.BundleHash, nil, nil
}

func (f *FakeBackendService) ExtendBundle(bundleHash string, files map[lsp.DocumentURI]File, removedFiles []lsp.DocumentURI) ([]lsp.DocumentURI, error) {
	params := []interface{}{bundleHash, files, removedFiles}
	f.addCall(params, ExtendBundleWithSourceOperation)
	return nil, nil
}
func (f *FakeBackendService) RetrieveDiagnostics(bundleHash string, limitToFiles []lsp.DocumentURI, severity int) (map[lsp.DocumentURI][]lsp.Diagnostic, error) {
	params := []interface{}{bundleHash, limitToFiles, severity}
	f.addCall(params, RetrieveDiagnosticsOperation)

	diagnosticMap := map[lsp.DocumentURI][]lsp.Diagnostic{}
	var diagnostics []lsp.Diagnostic
	diagnosticMap[FakeDiagnosticUri] = append(diagnostics, FakeDiagnostic)
	return diagnosticMap, nil
}
