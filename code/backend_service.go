package code

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/lsp"
)

var (
	severities = map[string]sglsp.DiagnosticSeverity{
		"3":       sglsp.Error,
		"2":       sglsp.Warning,
		"warning": sglsp.Warning, // Sarif Level
		"error":   sglsp.Error,   // Sarif Level
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

func (s *SnykCodeBackendService) CreateBundle(files map[sglsp.DocumentURI]File) (string, []sglsp.DocumentURI, error) {
	log.Debug().Str("method", "CreateBundle").Msg("API: Creating bundle for " + strconv.Itoa(len(files)) + " files")
	requestBody, err := json.Marshal(files)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.doCall("POST", "/bundle", requestBody)
	if err != nil {
		return "", nil, err
	}

	var bundle bundleResponse
	err = json.Unmarshal(responseBody, &bundle)
	if err != nil {
		return "", nil, err
	}
	log.Debug().Str("method", "CreateBundle").Str("bundleHash", bundle.BundleHash).Msg("API: Create done")
	return bundle.BundleHash, bundle.MissingFiles, nil
}

func (s *SnykCodeBackendService) doCall(method string, path string, requestBody []byte) ([]byte, error) {
	b := bytes.NewBuffer(requestBody)
	req, err := http.NewRequest(method, environment.ApiUrl()+path, b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Session-Token", environment.Token())
	req.Header.Set("Content-Type", "application/json")

	log.Trace().Str("requestBody", string(requestBody)).Msg("SEND TO REMOTE")
	response, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Err(err).Msg("Couldn't close response body in call to Snyk Code")
		}
	}(response.Body)
	responseBody, err := ioutil.ReadAll(response.Body)
	log.Trace().Str("responseBody", string(responseBody)).Msg("RECEIVED FROM REMOTE")
	if err != nil {
		return nil, err
	}
	return responseBody, err
}

func (s *SnykCodeBackendService) ExtendBundle(bundleHash string, files map[sglsp.DocumentURI]File, removedFiles []sglsp.DocumentURI) (string, []sglsp.DocumentURI, error) {
	log.Debug().Str("method", "ExtendBundle").Str("bundleHash", bundleHash).Msg("API: Extending bundle " + bundleHash + " for " + strconv.Itoa(len(files)) + " files")
	defer log.Debug().Str("method", "ExtendBundle").Str("bundleHash", bundleHash).Msg("API: Extend done")

	requestBody, err := json.Marshal(extendBundleRequest{
		Files:        files,
		RemovedFiles: removedFiles,
	})
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.doCall("PUT", "/bundle/"+bundleHash, requestBody)
	if err != nil {
		return "", nil, err
	}
	var bundleResponse bundleResponse
	err = json.Unmarshal(responseBody, &bundleResponse)
	return bundleResponse.BundleHash, bundleResponse.MissingFiles, err
}

func (s *SnykCodeBackendService) RunAnalysis(bundleHash string, shardKey string, limitToFiles []sglsp.DocumentURI, severity int) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]sglsp.CodeLens, string, error) {
	requestBody, err := s.analysisRequestBody(bundleHash, shardKey, limitToFiles, severity)
	if err != nil {
		log.Err(err).Str("method", "RunAnalysis").Str("requestBody", string(requestBody)).Msg("error creating request body")
		return nil, nil, "", err
	}

	responseBody, err := s.doCall("POST", "/analysis", requestBody)
	failed := "FAILED"
	if err != nil {
		log.Err(err).Str("method", "RunAnalysis").Str("responseBody", string(responseBody)).Msg("error response from analysis")
		return nil, nil, failed, err
	}

	var response SarifResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		log.Err(err).Str("method", "RunAnalysis").Str("responseBody", string(responseBody)).Msg("error unmarshalling")
		return nil, nil, failed, err
	}

	log.Debug().Str("method", "RunAnalysis").
		Str("bundleHash", bundleHash).Float32("progress", response.Progress).Msgf("Status: %s", response.Status)

	if response.Status == failed {
		log.Err(err).Str("method", "RunAnalysis").Str("responseStatus", response.Status).Msg("analysis failed")
		return nil, nil, failed, SnykAnalysisFailedError{Msg: string(responseBody)}
	}

	if response.Status == "" {
		log.Err(err).Str("method", "RunAnalysis").Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return nil, nil, failed, SnykAnalysisFailedError{Msg: string(responseBody)}
	}

	if response.Status != "COMPLETE" {
		return nil, nil, response.Status, nil
	}
	diags, lenses := s.convertSarifResponse(response)
	return diags, lenses, response.Status, err
}

func (s *SnykCodeBackendService) analysisRequestBody(bundleHash string, shardKey string, limitToFiles []sglsp.DocumentURI, severity int) ([]byte, error) {
	request := AnalysisRequest{
		Key: AnalysisRequestKey{
			Type:         "file",
			Hash:         bundleHash,
			LimitToFiles: limitToFiles,
		},
		Legacy: false,
	}
	if len(shardKey) > 0 {
		request.Key.Shard = shardKey
	}
	if severity > 0 {
		request.Severity = severity
	}

	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (s *SnykCodeBackendService) convertSarifResponse(response SarifResponse) (
	map[sglsp.DocumentURI][]lsp.Diagnostic,
	map[sglsp.DocumentURI][]sglsp.CodeLens,
) {
	diags := make(map[sglsp.DocumentURI][]lsp.Diagnostic)
	lenses := make(map[sglsp.DocumentURI][]sglsp.CodeLens)
	runs := response.Sarif.Runs
	if len(runs) == 0 {
		return diags, lenses
	}
	for _, result := range runs[0].Results {
		for _, loc := range result.Locations {
			uri := sglsp.DocumentURI(loc.PhysicalLocation.ArtifactLocation.URI)
			diagSlice := diags[uri]
			lensSlice := lenses[uri]

			myRange := sglsp.Range{
				Start: sglsp.Position{
					Line:      loc.PhysicalLocation.Region.StartLine - 1,
					Character: loc.PhysicalLocation.Region.StartColumn - 1,
				},
				End: sglsp.Position{
					Line:      loc.PhysicalLocation.Region.EndLine - 1,
					Character: loc.PhysicalLocation.Region.EndColumn,
				},
			}
			d := lsp.Diagnostic{
				Range:    myRange,
				Severity: lspSeverity(result.Level),
				Code:     result.RuleID,
				Source:   "Snyk LSP",
				Message:  result.Message.Text,
			}
			l := sglsp.CodeLens{
				Range: myRange,
				Command: sglsp.Command{
					Title:     "Open " + result.RuleID,
					Command:   "snyk.showRule",
					Arguments: []interface{}{result.RuleID}},
			}
			diagSlice = append(diagSlice, d)
			lensSlice = append(lensSlice, l)
			diags[uri] = diagSlice
			lenses[uri] = lensSlice
		}
	}
	return diags, lenses
}
