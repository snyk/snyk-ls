package code

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/snyk/snyk-lsp/lsp"
	sglsp "github.com/sourcegraph/go-lsp"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	TokenEnvVariable        = "SNYK_TOKEN"
	ApiUrl           string = "https://deeproxy.snyk.io"
)

var (
	severities = map[string]sglsp.DiagnosticSeverity{
		"high": sglsp.Error,
		"low":  sglsp.Warning,
	}
)

func lspSeverity(snykSeverity string) sglsp.DiagnosticSeverity {
	lspSev, ok := severities[snykSeverity]
	if !ok {
		return sglsp.Info
	}
	return lspSev
}

type SnykCodeBackendService struct {
	client http.Client
}

type bundleResponse struct {
	BundleHash   string              `json:"bundleHash"`
	MissingFiles []sglsp.DocumentURI `json:"missingFiles"`
}

type extendBundleRequest struct {
	Files        map[sglsp.DocumentURI]File `json:"files"`
	RemovedFiles []sglsp.DocumentURI        `json:"removedFiles,omitempty"`
}

func token() string {
	token, exist := os.LookupEnv(TokenEnvVariable)
	if exist == false {
		token = ""
	}
	return token
}

func (s *SnykCodeBackendService) CreateBundle(files map[sglsp.DocumentURI]File) (string, []sglsp.DocumentURI, error) {
	requestBody, err := json.Marshal(files)
	if err != nil {
		return "", nil, err
	}

	b := bytes.NewBuffer(requestBody)
	responseBody, err := s.doCall("POST", "/bundle", b)
	if err != nil {
		return "", nil, err
	}

	var bundle bundleResponse
	err = json.Unmarshal(responseBody, &bundle)
	if err != nil {
		return "", nil, err
	}
	return bundle.BundleHash, bundle.MissingFiles, nil
}

func (s *SnykCodeBackendService) doCall(method string, path string, requestBody io.Reader) ([]byte, error) {
	logger := logrus.New()
	req, err := http.NewRequest(method, ApiUrl+path, requestBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Session-Token", token())
	req.Header.Set("Content-Type", "application/json")

	logger.Info(req.Body)
	response, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	logger.Info(string(responseBody))
	if err != nil {
		return nil, err
	}
	return responseBody, err
}

func (s *SnykCodeBackendService) ExtendBundle(bundleHash string, files map[sglsp.DocumentURI]File, removedFiles []sglsp.DocumentURI) (string, []sglsp.DocumentURI, error) {
	requestBody, err := json.Marshal(extendBundleRequest{
		Files:        files,
		RemovedFiles: removedFiles,
	})
	if err != nil {
		return "", nil, err
	}
	b := bytes.NewBuffer(requestBody)

	responseBody, err := s.doCall("PUT", "/bundle/"+bundleHash, b)
	if err != nil {
		return "", nil, err
	}
	var bundleResponse bundleResponse
	err = json.Unmarshal(responseBody, &bundleResponse)
	return bundleResponse.BundleHash, bundleResponse.MissingFiles, err
}

func (s *SnykCodeBackendService) RetrieveDiagnostics(bundleHash string, limitToFiles []sglsp.DocumentURI, severity int) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]sglsp.CodeLens, string, error) {
	requestBody, err := s.analysisRequestBody(bundleHash, limitToFiles, severity)
	if err != nil {
		return nil, nil, "", err
	}

	b := bytes.NewBuffer(requestBody)
	responseBody, err := s.doCall("POST", "/analysis", b)
	failed := "FAILED"
	if err != nil {
		return nil, nil, failed, err
	}

	var response AnalysisResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return nil, nil, "", err
	}
	if response.Status == failed {
		return nil, nil, "", SnykAnalysisFailedError{Msg: string(responseBody)}
	}
	if response.Status != "COMPLETE" {
		return nil, nil, "", nil
	}
	diags, lenses := s.convert(response)
	return diags, lenses, response.Status, err
}

func (s *SnykCodeBackendService) analysisRequestBody(bundleHash string, limitToFiles []sglsp.DocumentURI, severity int) ([]byte, error) {
	request := AnalysisRequest{
		Key: AnalysisRequestKey{
			Type:         "file",
			Hash:         bundleHash,
			LimitToFiles: limitToFiles,
		},
		Legacy: true,
	}
	if severity > 0 {
		request.Severity = severity
	}
	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (s *SnykCodeBackendService) convert(
	response AnalysisResponse,
) (
	map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]sglsp.CodeLens) {
	// todo convert to code lenses
	diags := make(map[sglsp.DocumentURI][]lsp.Diagnostic)
	lenses := make(map[sglsp.DocumentURI][]sglsp.CodeLens)
	for uri, fileSuggestions := range response.Files {
		diagSlice := make([]lsp.Diagnostic, 0)
		lensSlice := make([]sglsp.CodeLens, 0)
		for index := range fileSuggestions {
			fileSuggestion := fileSuggestions[index]
			suggestion := response.Suggestions[index]
			for _, filePosition := range fileSuggestion {
				myRange := sglsp.Range{
					Start: sglsp.Position{
						Line:      filePosition.Rows[0],
						Character: filePosition.Rows[0],
					},
					End: sglsp.Position{
						Line:      filePosition.Rows[1],
						Character: filePosition.Cols[1],
					},
				}
				d := lsp.Diagnostic{
					Range:    myRange,
					Severity: lspSeverity(fmt.Sprintf("%d", suggestion.Severity)),
					Code:     suggestion.Rule,
					Source:   "snyk code",
					Message:  suggestion.Message,
				}
				l := sglsp.CodeLens{
					Range: myRange,
					Command: sglsp.Command{
						Title:     "Open " + suggestion.Rule,
						Command:   "snyk.showRule",
						Arguments: []interface{}{suggestion.Rule}},
				}
				diagSlice = append(diagSlice, d)
				lensSlice = append(lensSlice, l)
			}
		}
		diags[uri] = diagSlice
		lenses[uri] = lensSlice
	}
	return diags, lenses
}
