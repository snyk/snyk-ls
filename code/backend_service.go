package code

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"strconv"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/code/encoding"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/observability/instrumentation"
	"github.com/snyk/snyk-ls/internal/uri"
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

type SnykCodeHTTPClient struct {
	client http.Client
	host   string
}

type bundleResponse struct {
	BundleHash   string              `json:"bundleHash"`
	MissingFiles []sglsp.DocumentURI `json:"missingFiles"`
}

type extendBundleRequest struct {
	Files        map[sglsp.DocumentURI]BundleFile `json:"files"`
	RemovedFiles []sglsp.DocumentURI              `json:"removedFiles,omitempty"`
}

type filtersResponse struct {
	ConfigFiles []string `json:"configFiles" pact:"min=1"`
	Extensions  []string `json:"extensions" pact:"min=1"`
}

func NewHTTPRepository(host string) *SnykCodeHTTPClient {
	return &SnykCodeHTTPClient{http.Client{}, host}
}

func (s *SnykCodeHTTPClient) GetFilters(ctx context.Context) (configFiles []string, extensions []string, err error) {
	log.Debug().Str("method", "GetFilters").Msg("API: Getting file extension filters")
	responseBody, err := s.doCall(ctx, "GET", "/filters", nil)
	if err != nil {
		return nil, nil, err
	}

	var filters filtersResponse
	err = json.Unmarshal(responseBody, &filters)
	if err != nil {
		return nil, nil, err
	}
	log.Debug().Str("method", "GetFilters").Msg("API: Finished getting filters")
	return filters.ConfigFiles, filters.Extensions, nil
}

func (s *SnykCodeHTTPClient) CreateBundle(
	ctx context.Context,
	files map[sglsp.DocumentURI]BundleFile,
) (string, []sglsp.DocumentURI, error) {
	log.Debug().Str("method", "CreateBundle").Msg("API: Creating bundle for " + strconv.Itoa(len(files)) + " files")
	requestBody, err := json.Marshal(files)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.doCall(ctx, "POST", "/bundle", requestBody)
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

func (s *SnykCodeHTTPClient) doCall(ctx context.Context, method string, path string, requestBody []byte) ([]byte, error) {

	span := instrumentation.StartSpan(ctx, "doCall")
	defer span.Finish()

	b := new(bytes.Buffer)

	mustBeEncoded := method == http.MethodPost || method == http.MethodPut
	if mustBeEncoded {
		enc := encoding.NewEncoder(b)
		_, err := enc.Write(requestBody)
		if err != nil {
			return nil, err
		}
	} else {
		b = bytes.NewBuffer(requestBody)
	}

	req, err := http.NewRequest(method, s.host+path, b)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Session-Token", config.CurrentConfig().Token())
	// https://www.keycdn.com/blog/http-cache-headers
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	if mustBeEncoded {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}

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

func (s *SnykCodeHTTPClient) ExtendBundle(
	ctx context.Context,
	bundleHash string,
	files map[sglsp.DocumentURI]BundleFile,
	removedFiles []sglsp.DocumentURI,
) (string, []sglsp.DocumentURI, error) {
	log.Debug().Str("method", "ExtendBundle").Str("bundleHash", bundleHash).Msg("API: Extending bundle " + bundleHash + " for " + strconv.Itoa(len(files)) + " files")
	defer log.Debug().Str("method", "ExtendBundle").Str("bundleHash", bundleHash).Msg("API: Extend done")

	requestBody, err := json.Marshal(extendBundleRequest{
		Files:        files,
		RemovedFiles: removedFiles,
	})
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.doCall(ctx, "PUT", "/bundle/"+bundleHash, requestBody)
	if err != nil {
		return "", nil, err
	}
	var bundleResponse bundleResponse
	err = json.Unmarshal(responseBody, &bundleResponse)
	return bundleResponse.BundleHash, bundleResponse.MissingFiles, err
}

type AnalysisStatus struct {
	message    string
	percentage int
}

func (s *SnykCodeHTTPClient) RunAnalysis(
	ctx context.Context,
	bundleHash string,
	shardKey string,
	limitToFiles []sglsp.DocumentURI,
	severity int,
) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]lsp.HoverDetails, AnalysisStatus, error) {
	log.Debug().Str("method", "RunAnalysis").Str("bundleHash", bundleHash).Msg("API: Retrieving analysis for bundle")
	defer log.Debug().Str("method", "RunAnalysis").Str("bundleHash", bundleHash).Msg("API: Retrieving analysis done")

	requestBody, err := s.analysisRequestBody(bundleHash, shardKey, limitToFiles, severity)
	if err != nil {
		log.Err(err).Str("method", "RunAnalysis").Str("requestBody", string(requestBody)).Msg("error creating request body")
		return nil, nil, AnalysisStatus{}, err
	}

	responseBody, err := s.doCall(ctx, "POST", "/analysis", requestBody)
	failed := AnalysisStatus{message: "FAILED"}
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
		Str("bundleHash", bundleHash).Float64("progress", response.Progress).Msgf("Status: %s", response.Status)

	if response.Status == failed.message {
		log.Err(err).Str("method", "RunAnalysis").Str("responseStatus", response.Status).Msg("analysis failed")
		return nil, nil, failed, SnykAnalysisFailedError{Msg: string(responseBody)}
	}

	if response.Status == "" {
		log.Err(err).Str("method", "RunAnalysis").Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return nil, nil, failed, SnykAnalysisFailedError{Msg: string(responseBody)}
	}
	status := AnalysisStatus{message: response.Status, percentage: int(math.RoundToEven(response.Progress * 100))}
	if response.Status != "COMPLETE" {
		return nil, nil, status, nil
	}

	diags, hovers := s.convertSarifResponse(response)
	return diags, hovers, status, err
}

func (s *SnykCodeHTTPClient) analysisRequestBody(bundleHash string, shardKey string, limitToFiles []sglsp.DocumentURI, severity int) ([]byte, error) {
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

func (s *SnykCodeHTTPClient) convertSarifResponse(response SarifResponse) (
	map[sglsp.DocumentURI][]lsp.Diagnostic,
	map[sglsp.DocumentURI][]lsp.HoverDetails,
) {
	diags := make(map[sglsp.DocumentURI][]lsp.Diagnostic)
	hovers := make(map[sglsp.DocumentURI][]lsp.HoverDetails)

	runs := response.Sarif.Runs
	if len(runs) == 0 {
		return diags, hovers
	}

	for _, result := range runs[0].Results {
		for _, loc := range result.Locations {
			// convert the documentURI to a path according to our conversion
			path := uri.PathFromUri(sglsp.DocumentURI(loc.PhysicalLocation.ArtifactLocation.URI))
			// then convert it back to cater for special cases under windows
			documentURI := uri.PathToUri(path)

			diagSlice := diags[documentURI]
			hoverSlice := hovers[documentURI]

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
				Message:  fmt.Sprintf("Vulnerability Id: %s", result.RuleID),
			}

			diagSlice = append(diagSlice, d)
			diags[documentURI] = diagSlice

			h := lsp.HoverDetails{
				Id:    result.RuleID,
				Range: myRange,
				// Todo: Add more details here
				Message: fmt.Sprintf("Snyk: %s \n", result.Message.Text),
			}

			hoverSlice = append(hoverSlice, h)
			hovers[documentURI] = hoverSlice
		}
	}
	return diags, hovers
}
