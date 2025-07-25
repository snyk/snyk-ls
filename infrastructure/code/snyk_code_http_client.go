/*
 * © 2022-2024 Snyk Limited
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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	codeClientObservability "github.com/snyk/code-client-go/observability"
	codeClientSarif "github.com/snyk/code-client-go/sarif"

	performance2 "github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/code/encoding"
)

const (
	completeStatus                = "COMPLETE"
	codeDescriptionURL            = "https://docs.snyk.io/scan-using-snyk/snyk-code/snyk-code-security-rules"
	failedToObtainRequestIdString = "Failed to obtain request id. "
)

var (
	issueSeverities = map[string]types.Severity{
		"3":       types.High,
		"2":       types.Medium,
		"warning": types.Medium, // Sarif Level
		"error":   types.High,   // Sarif Level
	}
)

var codeApiRegex = regexp.MustCompile(`^(deeproxy\.)?`)

func issueSeverity(snykSeverity string) types.Severity {
	sev, ok := issueSeverities[snykSeverity]
	if !ok {
		return types.Low
	}
	return sev
}

type SnykCodeHTTPClient struct {
	client        func() *http.Client
	instrumentor  codeClientObservability.Instrumentor
	errorReporter codeClientObservability.ErrorReporter
	c             *config.Config
}

type bundleResponse struct {
	BundleHash   string           `json:"bundleHash"`
	MissingFiles []types.FilePath `json:"missingFiles"`
}

type extendBundleRequest struct {
	Files        map[types.FilePath]BundleFile `json:"files"`
	RemovedFiles []types.FilePath              `json:"removedFiles,omitempty"`
}

type FiltersResponse struct {
	ConfigFiles []string `json:"configFiles" pact:"min=1"`
	Extensions  []string `json:"extensions" pact:"min=1"`
}

func NewSnykCodeHTTPClient(
	c *config.Config,
	instrumentor codeClientObservability.Instrumentor,
	errorReporter codeClientObservability.ErrorReporter,
	client func() *http.Client,
) *SnykCodeHTTPClient {
	return &SnykCodeHTTPClient{client, instrumentor, errorReporter, c}
}

func (s *SnykCodeHTTPClient) GetFilters(ctx context.Context) (
	filters FiltersResponse,
	err error,
) {
	method := "code.GetFilters"
	s.c.Logger().Debug().Str("method", method).Msg("API: Getting file extension filters")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	body, _, err := s.doCall(span.Context(), "GET", "/filters", nil)
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}

	err = json.Unmarshal(body, &filters)
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}
	s.c.Logger().Debug().Str("method", method).Msg("API: Finished getting filters")
	return filters, nil
}

func (s *SnykCodeHTTPClient) CreateBundle(
	ctx context.Context,
	filesToFilehashes map[types.FilePath]string,
) (string, []types.FilePath, error) {
	method := "code.CreateBundle"
	s.c.Logger().Debug().Str("method", method).Msg("API: Creating bundle for " + strconv.Itoa(len(filesToFilehashes)) + " files")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestBody, err := json.Marshal(filesToFilehashes)
	if err != nil {
		return "", nil, err
	}

	body, _, err := s.doCall(span.Context(), "POST", "/bundle", requestBody)
	if err != nil {
		return "", nil, err
	}

	var bundle bundleResponse
	err = json.Unmarshal(body, &bundle)
	if err != nil {
		return "", nil, err
	}
	s.c.Logger().Debug().Str("method", method).Msg("API: Create done")
	return bundle.BundleHash, bundle.MissingFiles, nil
}

func (s *SnykCodeHTTPClient) doCall(ctx context.Context, method string, path string, requestBody []byte) ([]byte, int, error) {
	span := s.instrumentor.StartSpan(ctx, "code.doCall")
	defer s.instrumentor.Finish(span)

	const retryCount = 3

	// we only retry, if we get a retryable http status code
	for i := 0; i < retryCount; i++ {
		requestId, err := performance2.GetTraceId(span.Context())
		if err != nil {
			return nil, 0, errors.New("Code request id was not provided. " + err.Error())
		}

		bodyBuffer, err := s.encodeIfNeeded(method, requestBody)
		if err != nil {
			return nil, 0, err
		}

		c := config.CurrentConfig()
		req, err := s.newRequest(c, method, path, bodyBuffer, requestId)
		if err != nil {
			return nil, 0, err
		}

		s.c.Logger().Trace().Str("requestBody", string(requestBody)).Str("snyk-request-id", requestId).Msg("SEND TO REMOTE")

		responseBody, httpStatusCode, err := s.httpCall(req)

		if responseBody != nil {
			s.c.Logger().Trace().Int("response.Status", httpStatusCode).
				Str("responseBody", string(responseBody)).
				Str("snyk-request-id", requestId).
				Msg("RECEIVED FROM REMOTE")
		} else {
			s.c.Logger().Trace().
				Str("snyk-request-id", requestId).
				Msg("RECEIVED FROM REMOTE")
		}

		if err != nil {
			return nil, 0, err // no retries for errors
		}

		err = s.checkResponseCode(httpStatusCode)
		if err != nil {
			if retryErrorCodes[httpStatusCode] {
				s.c.Logger().Debug().Err(err).Str("method", method).Int("attempts done", i+1).Msgf("retrying")
				if i < retryCount-1 {
					time.Sleep(5 * time.Second)
					continue
				}
				// return the error on last try
				return nil, httpStatusCode, err
			}
			return nil, httpStatusCode, err
		}
		// no error, we can break the retry loop
		return responseBody, httpStatusCode, nil
	}
	return nil, 0, nil
}

func (s *SnykCodeHTTPClient) httpCall(req *http.Request) ([]byte, int, error) {
	method := "code.httpCall"
	logger := s.c.Logger().With().Str("method", method).Logger()
	statusCode := 0

	response, err := s.client().Do(req)
	if err != nil {
		logger.Err(err).Msgf("got http error")
		return nil, statusCode, err
	}

	if response == nil {
		return nil, 0, nil
	}

	defer func() {
		bodyCloseErr := response.Body.Close()
		if bodyCloseErr != nil {
			logger.Err(bodyCloseErr).Msg("failed to close response body")
		}
	}()

	statusCode = response.StatusCode
	responseBody, readErr := io.ReadAll(response.Body)

	if readErr != nil {
		logger.Err(readErr).Msg("failed to read response body")
		return responseBody, statusCode, err
	}
	return responseBody, statusCode, nil
}

func (s *SnykCodeHTTPClient) newRequest(
	c *config.Config,
	method string,
	path string,
	body *bytes.Buffer,
	requestId string,
) (*http.Request, error) {
	host, err := GetCodeApiUrl(c)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, host+path, body)
	if err != nil {
		return nil, err
	}

	s.addOrganization(c, req)
	s.addDefaultHeaders(req, requestId, method)
	return req, nil
}

func (s *SnykCodeHTTPClient) addDefaultHeaders(req *http.Request, requestId string, method string) {
	req.Header.Set("snyk-request-id", requestId)
	// https://www.keycdn.com/blog/http-cache-headers
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	if s.mustBeEncoded(method) {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
}

func (s *SnykCodeHTTPClient) addOrganization(c *config.Config, req *http.Request) {
	// Setting a chosen org name for the request
	org := c.Organization()
	if org != "" {
		req.Header.Set("snyk-org-name", org)
	}
}

func (s *SnykCodeHTTPClient) encodeIfNeeded(method string, requestBody []byte) (*bytes.Buffer, error) {
	b := new(bytes.Buffer)
	mustBeEncoded := s.mustBeEncoded(method)
	if mustBeEncoded {
		enc := encoding.NewEncoder(b)
		_, err := enc.Write(requestBody)
		if err != nil {
			return nil, err
		}
	} else {
		b = bytes.NewBuffer(requestBody)
	}
	return b, nil
}

func (s *SnykCodeHTTPClient) mustBeEncoded(method string) bool {
	return method == http.MethodPost || method == http.MethodPut
}

var retryErrorCodes = map[int]bool{
	http.StatusServiceUnavailable:  true,
	http.StatusBadGateway:          true,
	http.StatusGatewayTimeout:      true,
	http.StatusInternalServerError: true,
}

func (s *SnykCodeHTTPClient) ExtendBundle(ctx context.Context, bundleHash string, files map[types.FilePath]BundleFile, removedFiles []types.FilePath) (string, []types.FilePath, error) {
	method := "code.ExtendBundle"
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)
	requestId, err := performance2.GetTraceId(span.Context())
	logger := s.c.Logger().With().Str("method", method).Str("requestId", requestId).Logger()
	if err != nil {
		logger.Err(err).Msg("failed to get request id")
	}

	logger.Debug().Msg("API: Extending bundle for " + strconv.Itoa(len(files)) + " files")
	defer logger.Debug().Msg("API: Extend done")

	requestBody, err := json.Marshal(extendBundleRequest{
		Files:        files,
		RemovedFiles: removedFiles,
	})
	if err != nil {
		return "", nil, err
	}

	responseBody, httpStatus, err := s.doCall(span.Context(), "PUT", "/bundle/"+bundleHash, requestBody)
	if httpStatus == http.StatusBadRequest {
		logger.Err(err).Msg("got an HTTP 400 Bad Request, dumping bundle infos for analysis")
		logger.Error().Any("fileHashes", files).Send()
		logger.Error().Any("removedFiles", removedFiles).Send()
	}
	if err != nil {
		return "", nil, err
	}
	var bundleResp bundleResponse
	err = json.Unmarshal(responseBody, &bundleResp)
	return bundleResp.BundleHash, bundleResp.MissingFiles, err
}

type AnalysisStatus struct {
	message    string
	percentage int
}

func (s *SnykCodeHTTPClient) RunAnalysis(
	ctx context.Context,
	options AnalysisOptions,
	baseDir types.FilePath,
) ([]types.Issue, AnalysisStatus, error) {
	method := "code.RunAnalysis"
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestId, err := performance2.GetTraceId(span.Context())
	if err != nil {
		s.c.Logger().Err(err).Str("method", method).Msg(failedToObtainRequestIdString + err.Error())
		return nil, AnalysisStatus{}, err
	}
	s.c.Logger().Debug().Str("method", method).Str("requestId", requestId).Msg("API: Retrieving analysis for bundle")
	defer s.c.Logger().Debug().Str("method", method).Str("requestId", requestId).Msg("API: Retrieving analysis done")

	requestBody, err := s.analysisRequestBody(&options)
	if err != nil {
		s.c.Logger().Err(err).Str("method", method).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return nil, AnalysisStatus{}, err
	}

	responseBody, _, err := s.doCall(span.Context(), "POST", "/analysis", requestBody)
	failed := AnalysisStatus{message: "FAILED"}
	if err != nil {
		s.c.Logger().Err(err).Str("method", method).Str("responseBody", string(responseBody)).Msg("error response from analysis")
		return nil, failed, err
	}

	var response codeClientSarif.SarifResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		s.c.Logger().Err(err).Str("method", method).Str("responseBody", string(responseBody)).Msg("error unmarshalling")
		return nil, failed, err
	} else {
		logSarifResponse(method, response, s.c.Logger())
	}

	s.c.Logger().Debug().Str("method", method).Str("requestId", requestId).Float64("progress",
		response.Progress).Msgf("Status: %s", response.Status)

	if response.Status == failed.message {
		s.c.Logger().Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("analysis failed")
		return nil, failed, SnykAnalysisFailedError{Msg: string(responseBody)}
	}

	if response.Status == "" {
		s.c.Logger().Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return nil, failed, SnykAnalysisFailedError{Msg: string(responseBody)}
	}
	status := AnalysisStatus{message: response.Status, percentage: int(math.RoundToEven(response.Progress * 100))}
	if response.Status != completeStatus {
		return nil, status, nil
	}

	converter := SarifConverter{sarif: response, hoverVerbosity: s.c.HoverVerbosity(), logger: s.c.Logger()}
	issues, err := converter.toIssues(baseDir)
	return issues, status, err
}

func logSarifResponse(method string, sarifResponse codeClientSarif.SarifResponse, logger *zerolog.Logger) {
	logger.Debug().
		Str("method", method).
		Str("status", sarifResponse.Status).
		Float64("progress", sarifResponse.Progress).
		Int("fetchingCodeTime", sarifResponse.Timing.FetchingCode).
		Int("analysisTime", sarifResponse.Timing.Analysis).
		Int("filesAnalyzed", len(sarifResponse.Coverage)).
		Msg("Received response summary")
}

func (s *SnykCodeHTTPClient) analysisRequestBody(options *AnalysisOptions) ([]byte, error) {
	request := AnalysisRequest{
		Key: AnalysisRequestKey{
			Type:         "file",
			Hash:         options.bundleHash,
			LimitToFiles: options.limitToFiles,
		},
		Legacy:          false,
		AnalysisContext: newCodeRequestContext(),
	}
	if len(options.shardKey) > 0 {
		request.Key.Shard = options.shardKey
	}
	if options.severity > 0 {
		request.Severity = options.severity
	}

	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (s *SnykCodeHTTPClient) checkResponseCode(statusCode int) error {
	if statusCode >= 200 && statusCode <= 400 {
		return nil
	}
	return fmt.Errorf("Unexpected response code: %d", statusCode)
}

func GetCodeApiUrl(c *config.Config) (string, error) {
	if !c.IsFedramp() {
		return c.SnykCodeApi(), nil
	}
	u, err := url.Parse(c.SnykCodeApi())
	if err != nil {
		return "", err
	}

	u.Host = codeApiRegex.ReplaceAllString(u.Host, "api.")

	if c.Organization() == "" {
		return "", errors.New("Organization is required in a fedramp environment")
	}

	u.Path = "/hidden/orgs/" + c.Organization() + "/code"

	return u.String(), nil
}
