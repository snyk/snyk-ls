package code

import (
	"bytes"
	"encoding/json"
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

type SnykCodeBackendService struct {
	client http.Client
}

type createBundleResponse struct {
	BundleHash   string              `json:"bundleHash"`
	MissingFiles []sglsp.DocumentURI `json:"missingFiles"`
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

	var bundle createBundleResponse
	err = json.Unmarshal(responseBody, &bundle)
	if err != nil {
		return "", nil, err
	}
	return bundle.BundleHash, bundle.MissingFiles, nil
}

func (s *SnykCodeBackendService) doCall(method string, path string, requestBody io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, ApiUrl+path, requestBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Session-Token", token())
	req.Header.Set("Content-Type", "application/json")

	response, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return responseBody, err
}

func (s *SnykCodeBackendService) ExtendBundle(bundleHash string, files map[sglsp.DocumentURI]File, removedFiles []sglsp.DocumentURI) ([]sglsp.DocumentURI, error) {
	requestBody, err := json.Marshal(files)
	if err != nil {
		return nil, err
	}
	b := bytes.NewBuffer(requestBody)

	responseBody, err := s.doCall("PUT", "/bundle"+bundleHash, b)
	if err != nil {
		return nil, err
	}
	var missingFiles []sglsp.DocumentURI
	err = json.Unmarshal(responseBody, &missingFiles)
	return missingFiles, err
}

func (s *SnykCodeBackendService) RetrieveDiagnostics(bundleHash string, limitToFiles []sglsp.DocumentURI, severity int) (map[sglsp.DocumentURI][]lsp.Diagnostic, error) {
	requestBody, err := s.analysisRequestBody(bundleHash, limitToFiles, severity)
	if err != nil {
		return nil, err
	}

	b := bytes.NewBuffer(requestBody)
	responseBody, err := s.doCall("PUT", "/bundle"+bundleHash, b)
	if err != nil {
		return nil, err
	}

	var response AnalysisResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return nil, err
	}
	if response.Status == "FAILED" {
		return nil, SnykAnalysisFailedError{Msg: string(responseBody)}
	}
	if response.Status != "COMPLETE" {
		return nil, nil
	}
	return s.convertToDiagnostics(response), err
}

func (s *SnykCodeBackendService) analysisRequestBody(bundleHash string, limitToFiles []sglsp.DocumentURI, severity int) ([]byte, error) {
	request := AnalysisRequest{
		Key: AnalysisRequestKey{
			Type:         "file",
			Hash:         bundleHash,
			LimitToFiles: limitToFiles,
		},
		Severity:    severity,
		Prioritized: 0,
		Legacy:      true,
	}
	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (s *SnykCodeBackendService) convertToDiagnostics(response AnalysisResponse) map[sglsp.DocumentURI][]lsp.Diagnostic {

	//diagnostics := map[sglsp.DocumentURI][]sglsp.FakeDiagnostic{}
	//for uri, fileSuggestions := range response.Files {
	//	for index := range fileSuggestions {
	//		fileSuggestion := fileSuggestions[index]
	//		suggestion := response.Suggestions[index]
	//
	//			FakeDiagnostic := sglsp.FakeDiagnostic{
	//				Range: sglsp.Range{
	//					Start: sglsp.Position{
	//						Line:      filePosition,
	//						Character: 3,
	//					},
	//					End: sglsp.Position{
	//						Line:      0,
	//						Character: 7,
	//					},
	//				},
	//				Severity: sglsp.Error,
	//				Code:     "SNYK-123",
	//				Source:   "snyk code",
	//				Message:  "This is a dummy error (severity error)",
	//			}
	//
	//		}
	//	}
	//}

	// foreach FakeDiagnostic per uri
	//diagnostics = append(diagnostics, FakeDiagnostic)
	//return diagnostics
	return nil
}
