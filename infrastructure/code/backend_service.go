/*
 * © 2022 Snyk Limited All rights reserved.
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
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	performance2 "github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code/encoding"
)

const (
	completeStatus                = "COMPLETE"
	codeDescriptionURL            = "https://docs.snyk.io/scan-using-snyk/snyk-code/snyk-code-security-rules"
	failedToObtainRequestIdString = "Failed to obtain request id. "
)

var (
	issueSeverities = map[string]snyk.Severity{
		"3":       snyk.High,
		"2":       snyk.Medium,
		"warning": snyk.Medium, // Sarif Level
		"error":   snyk.High,   // Sarif Level
	}
)

var codeApiRegex = regexp.MustCompile(`^(deeproxy\.)?`)

func issueSeverity(snykSeverity string) snyk.Severity {
	sev, ok := issueSeverities[snykSeverity]
	if !ok {
		return snyk.Low
	}
	return sev
}

type SnykCodeHTTPClient struct {
	client        func() *http.Client
	instrumentor  performance2.Instrumentor
	errorReporter error_reporting.ErrorReporter
}

type bundleResponse struct {
	BundleHash   string   `json:"bundleHash"`
	MissingFiles []string `json:"missingFiles"`
}

type extendBundleRequest struct {
	Files        map[string]BundleFile `json:"files"`
	RemovedFiles []string              `json:"removedFiles,omitempty"`
}

type FiltersResponse struct {
	ConfigFiles []string `json:"configFiles" pact:"min=1"`
	Extensions  []string `json:"extensions" pact:"min=1"`
}

func NewHTTPRepository(
	instrumentor performance2.Instrumentor,
	errorReporter error_reporting.ErrorReporter,
	client func() *http.Client,
) *SnykCodeHTTPClient {
	return &SnykCodeHTTPClient{client, instrumentor, errorReporter}
}

func (s *SnykCodeHTTPClient) GetFilters(ctx context.Context) (
	filters FiltersResponse,
	err error,
) {
	method := "code.GetFilters"
	log.Debug().Str("method", method).Msg("API: Getting file extension filters")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	responseBody, err := s.doCall(span.Context(), "GET", "/filters", nil)
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}

	err = json.Unmarshal(responseBody, &filters)
	if err != nil {
		return FiltersResponse{ConfigFiles: nil, Extensions: nil}, err
	}
	log.Debug().Str("method", method).Msg("API: Finished getting filters")
	return filters, nil
}

func (s *SnykCodeHTTPClient) CreateBundle(
	ctx context.Context,
	filesToFilehashes map[string]string,
) (string, []string, error) {

	method := "code.CreateBundle"
	log.Debug().Str("method", method).Msg("API: Creating bundle for " + strconv.Itoa(len(filesToFilehashes)) + " files")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestBody, err := json.Marshal(filesToFilehashes)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.doCall(span.Context(), "POST", "/bundle", requestBody)
	if err != nil {
		return "", nil, err
	}

	var bundle bundleResponse
	err = json.Unmarshal(responseBody, &bundle)
	if err != nil {
		return "", nil, err
	}
	log.Debug().Str("method", method).Msg("API: Create done")
	return bundle.BundleHash, bundle.MissingFiles, nil
}

func (s *SnykCodeHTTPClient) doCall(ctx context.Context,
	method string,
	path string,
	requestBody []byte,
) (responseBody []byte, err error) {
	span := s.instrumentor.StartSpan(ctx, "code.doCall")
	defer s.instrumentor.Finish(span)

	const retryCount = 3
	for i := 0; i < retryCount; i++ {
		requestId, err := performance2.GetTraceId(span.Context())
		if err != nil {
			return nil, errors.New("Code request id was not provided. " + err.Error())
		}

		bodyBuffer, err := s.encodeIfNeeded(method, requestBody)
		if err != nil {
			return nil, err
		}

		c := config.CurrentConfig()
		req, err := s.newRequest(c, method, path, bodyBuffer, requestId)
		if err != nil {
			return nil, err
		}

		log.Trace().Str("requestBody", string(requestBody)).Str("snyk-request-id", requestId).Msg("SEND TO REMOTE")

		response, body, err := s.httpCall(req)
		responseBody = body

		if response != nil && responseBody != nil {
			log.Trace().Str("response.Status", response.Status).
				Str("responseBody", string(responseBody)).
				Str("snyk-request-id", requestId).
				Msg("RECEIVED FROM REMOTE")
		} else {
			log.Trace().
				Str("snyk-request-id", requestId).
				Msg("RECEIVED FROM REMOTE")
		}

		if err != nil {
			return nil, err // no retries for errors
		}

		err = s.checkResponseCode(response)
		if err != nil {
			if retryErrorCodes[response.StatusCode] {
				log.Debug().Err(err).Str("method", method).Int("attempts done", i+1).Msgf("retrying")
				if i < retryCount-1 {
					time.Sleep(5 * time.Second)
					continue
				}
				// return the error on last try
				return nil, err
			}
			return nil, err
		}
		// no error, we can break the retry loop
		break
	}
	return responseBody, err
}

func (s *SnykCodeHTTPClient) httpCall(req *http.Request) (*http.Response, []byte, error) {
	method := "code.httpCall"
	response, err := s.client().Do(req)
	if err != nil {
		log.Err(err).Str("method", method).Msgf("got http error")
		s.errorReporter.CaptureErrorAndReportAsIssue(req.RequestURI, err)
		return nil, nil, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Err(err).Msg("Couldn't close response body in call to Snyk Code")
		}
	}(response.Body)
	responseBody, err := io.ReadAll(response.Body)

	if err != nil {
		log.Err(err).Str("method", method).Msgf("error reading response body")
		s.errorReporter.CaptureErrorAndReportAsIssue(req.RequestURI, err)
		return nil, nil, err
	}
	return response, responseBody, nil
}

func (s *SnykCodeHTTPClient) newRequest(
	c *config.Config,
	method string,
	path string,
	body *bytes.Buffer,
	requestId string,
) (*http.Request, error) {

	host, err := getCodeApiUrl(c)
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

func (s *SnykCodeHTTPClient) ExtendBundle(
	ctx context.Context,
	bundleHash string,
	files map[string]BundleFile,
	removedFiles []string,
) (string, []string, error) {

	method := "code.ExtendBundle"
	log.Debug().Str("method", method).Msg("API: Extending bundle for " + strconv.Itoa(len(files)) + " files")
	defer log.Debug().Str("method", method).Msg("API: Extend done")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestBody, err := json.Marshal(extendBundleRequest{
		Files:        files,
		RemovedFiles: removedFiles,
	})
	if err != nil {
		return "", nil, err
	}

	responseBody, err := s.doCall(span.Context(), "PUT", "/bundle/"+bundleHash, requestBody)
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
	options AnalysisOptions,
	baseDir string,
) ([]snyk.Issue, AnalysisStatus, error) {
	method := "code.RunAnalysis"
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestId, err := performance2.GetTraceId(span.Context())
	if err != nil {
		log.Err(err).Str("method", method).Msg(failedToObtainRequestIdString + err.Error())
		return nil, AnalysisStatus{}, err
	}
	log.Debug().Str("method", method).Str("requestId", requestId).Msg("API: Retrieving analysis for bundle")
	defer log.Debug().Str("method", method).Str("requestId", requestId).Msg("API: Retrieving analysis done")

	requestBody, err := s.analysisRequestBody(&options)
	if err != nil {
		log.Err(err).Str("method", method).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return nil, AnalysisStatus{}, err
	}

	responseBody, err := s.doCall(span.Context(), "POST", "/analysis", requestBody)
	failed := AnalysisStatus{message: "FAILED"}
	if err != nil {
		log.Err(err).Str("method", method).Str("responseBody", string(responseBody)).Msg("error response from analysis")
		return nil, failed, err
	}

	var response SarifResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		log.Err(err).Str("method", method).Str("responseBody", string(responseBody)).Msg("error unmarshalling")
		return nil, failed, err
	} else {
		log.Debug().Str("responseBody", string(responseBody)).Msg("Received response")
	}

	log.Debug().Str("method", method).Str("requestId", requestId).Float64("progress",
		response.Progress).Msgf("Status: %s", response.Status)

	if response.Status == failed.message {
		log.Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("analysis failed")
		return nil, failed, SnykAnalysisFailedError{Msg: string(responseBody)}
	}

	if response.Status == "" {
		log.Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return nil, failed, SnykAnalysisFailedError{Msg: string(responseBody)}
	}
	status := AnalysisStatus{message: response.Status, percentage: int(math.RoundToEven(response.Progress * 100))}
	if response.Status != completeStatus {
		return nil, status, nil
	}

	issues, err := response.toIssues(baseDir)
	return issues, status, err
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

func (s *SnykCodeHTTPClient) checkResponseCode(r *http.Response) error {
	if r.StatusCode >= 200 && r.StatusCode <= 299 {
		return nil
	}
	return errors.New("Unexpected response code: " + r.Status)
}

type AutofixStatus struct {
	message string
}

func (s *SnykCodeHTTPClient) RunAutofix(
	ctx context.Context,
	options AutofixOptions,
	baseDir string,
) ([]AutofixSuggestion,
	AutofixStatus,
	error,
) {
	method := "code.RunAutofix"
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestId, err := performance2.GetTraceId(span.Context())
	if err != nil {
		log.Err(err).Str("method", method).Msg(failedToObtainRequestIdString + err.Error())
		return nil, AutofixStatus{}, err
	}
	log.Debug().Str("method", method).Str("requestId", requestId).Msg("API: Retrieving autofix for bundle")
	defer log.Debug().Str("method", method).Str("requestId", requestId).Msg("API: Retrieving autofix done")

	requestBody, err := s.autofixRequestBody(&options)
	if err != nil {
		log.Err(err).Str("method", method).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return nil, AutofixStatus{}, err
	}

	responseBody, err := s.doCall(span.Context(), "POST", "/autofix/suggestions", requestBody)
	failed := AutofixStatus{message: "FAILED"}
	if err != nil {
		log.Err(err).Str("method", method).Str("responseBody", string(responseBody)).Msg("error response from autofix")
		return nil, failed, err
	}

	var response AutofixResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		log.Err(err).Str("method", method).Str("responseBody", string(responseBody)).Msg("error unmarshalling")
		return nil, failed, err
	}

	log.Debug().Str("method", method).Str("requestId", requestId).Msgf("Status: %s", response.Status)

	if response.Status == failed.message {
		log.Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("autofix failed")
		return nil, failed, SnykAutofixFailedError{Msg: string(responseBody)}
	}

	if response.Status == "" {
		log.Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return nil, failed, SnykAutofixFailedError{Msg: string(responseBody)}
	}
	status := AutofixStatus{message: response.Status}
	if response.Status != completeStatus {
		return nil, status, nil
	}

	suggestions := response.toAutofixSuggestions(baseDir, options.filePath)
	return suggestions, AutofixStatus{message: response.Status}, nil
}

func (s *SnykCodeHTTPClient) autofixRequestBody(options *AutofixOptions) ([]byte, error) {
	_, ruleID, ok := getIssueLangAndRuleId(options.issue)
	if !ok {
		return nil, SnykAutofixFailedError{Msg: "Issue's ruleID does not follow <lang>/<ruleKey> format"}
	}

	request := AutofixRequest{
		Key: AutofixRequestKey{
			Type:     "file",
			Hash:     options.bundleHash,
			FilePath: options.filePath,
			RuleId:   ruleID,
			LineNum:  options.issue.Range.Start.Line + 1,
		},
		AnalysisContext: newCodeRequestContext(),
	}
	if len(options.shardKey) > 0 {
		request.Key.Shard = options.shardKey
	}

	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (s *SnykCodeHTTPClient) SubmitAutofixFeedback(ctx context.Context, fixId string, positive bool) error {
	method := "code.SubmitAutofixFeedback"
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestId, err := performance2.GetTraceId(span.Context())
	if err != nil {
		log.Err(err).Str("method", method).Msg(failedToObtainRequestIdString + err.Error())
		return err
	}

	log.Debug().Str("method", method).Str("requestId", requestId).Msg("API: Submitting Autofix feedback")
	defer log.Debug().Str("method", method).Str("requestId", requestId).Msg("API: Submitting Autofix feedback done")

	var feedback string
	if positive {
		feedback = "POSITIVE"
	} else {
		feedback = "NEGATIVE"
	}

	request := AutofixFeedback{
		FixId:           fixId,
		Feedback:        feedback,
		AnalysisContext: newCodeRequestContext(),
	}
	requestBody, err := json.Marshal(request)
	if err != nil {
		log.Err(err).Str("method", method).Str("requestBody", string(requestBody)).Msg("error creating request body for autofix feedback")
		return err
	}

	responseBody, err := s.doCall(span.Context(), "POST", "/autofix/feedback", requestBody)
	if err != nil {
		log.Err(err).Str("method", method).Str("responseBody", string(responseBody)).Msg("error response for autofix feedback")
		return err
	}

	return nil
}

func getCodeApiUrl(c *config.Config) (string, error) {
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
