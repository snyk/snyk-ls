package code

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"

	errors2 "github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	performance2 "github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code/encoding"
	"github.com/snyk/snyk-ls/internal/files"
	"github.com/snyk/snyk-ls/internal/httpclient"
	"github.com/snyk/snyk-ls/internal/uri"
)

const completeStatus = "COMPLETE"
const codeDescriptionURL = "https://docs.snyk.io/products/snyk-code/security-rules-used-by-snyk-code"

var (
	issueSeverities = map[string]snyk.Severity{
		"3":       snyk.High,
		"2":       snyk.Medium,
		"warning": snyk.Medium, // Sarif Level
		"error":   snyk.High,   // Sarif Level
	}
)

func issueSeverity(snykSeverity string) snyk.Severity {
	sev, ok := issueSeverities[snykSeverity]
	if !ok {
		return snyk.Low
	}
	return sev
}

type SnykCodeHTTPClient struct {
	client        http.Client
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

type filtersResponse struct {
	ConfigFiles []string `json:"configFiles" pact:"min=1"`
	Extensions  []string `json:"extensions" pact:"min=1"`
}

func NewHTTPRepository(instrumentor performance2.Instrumentor, errorReporter error_reporting.ErrorReporter) *SnykCodeHTTPClient {
	return &SnykCodeHTTPClient{*httpclient.NewHTTPClient(), instrumentor, errorReporter}
}

func (s *SnykCodeHTTPClient) GetFilters(ctx context.Context) (configFiles []string, extensions []string, err error) {
	method := "code.GetFilters"
	log.Debug().Str("method", method).Msg("API: Getting file extension filters")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	responseBody, err := s.doCall(span.Context(), "GET", "/filters", nil)
	if err != nil {
		return nil, nil, err
	}

	var filters filtersResponse
	err = json.Unmarshal(responseBody, &filters)
	if err != nil {
		return nil, nil, err
	}
	log.Debug().Str("method", method).Msg("API: Finished getting filters")
	return filters.ConfigFiles, filters.Extensions, nil
}

func (s *SnykCodeHTTPClient) CreateBundle(
	ctx context.Context,
	files map[string]string,
) (string, []string, error) {

	method := "code.CreateBundle"
	log.Debug().Str("method", method).Msg("API: Creating bundle for " + strconv.Itoa(len(files)) + " files")

	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestBody, err := json.Marshal(files)
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

func (s *SnykCodeHTTPClient) doCall(ctx context.Context, method string, path string, requestBody []byte) ([]byte, error) {
	span := s.instrumentor.StartSpan(ctx, "code.doCall")
	defer s.instrumentor.Finish(span)

	requestId, err := performance2.GetTraceId(ctx)
	if err != nil {
		return nil, errors.New("Code request id was not provided. " + err.Error())
	}

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

	host := config.CurrentConfig().SnykCodeApi()

	req, err := http.NewRequest(method, host+path, b)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Session-Token", config.CurrentConfig().Token())
	req.Header.Set("snyk-request-id", requestId)
	// https://www.keycdn.com/blog/http-cache-headers
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	if mustBeEncoded {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}

	log.Trace().Str("requestBody", string(requestBody)).Str("snyk-request-id", requestId).Msg("SEND TO REMOTE")
	response, err := s.client.Do(req)
	if err != nil {
		log.Err(err).Str("method", method).Msgf("got http error")
		s.errorReporter.CaptureError(err)
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Err(err).Msg("Couldn't close response body in call to Snyk Code")
		}
	}(response.Body)
	responseBody, err := ioutil.ReadAll(response.Body)
	log.Trace().Str("response.Status", response.Status).Str("responseBody", string(responseBody)).Str("snyk-request-id", requestId).Msg("RECEIVED FROM REMOTE")
	if err != nil {
		log.Err(err).Str("method", method).Msgf("error reading response body")
		s.errorReporter.CaptureError(err)
		return nil, err
	}

	err = checkResponseCode(response)
	if err != nil {
		return nil, err
	}

	return responseBody, err
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
) ([]snyk.Issue, AnalysisStatus, error) {
	method := "code.RunAnalysis"
	span := s.instrumentor.StartSpan(ctx, method)
	defer s.instrumentor.Finish(span)

	requestId, err := performance2.GetTraceId(span.Context())
	if err != nil {
		log.Err(err).Str("method", method).Msg("Failed to obtain request id. " + err.Error())
		return nil, AnalysisStatus{}, err
	}
	log.Debug().Str("method", method).Str("requestId", requestId).Msg("API: Retrieving analysis for bundle")
	defer log.Debug().Str("method", method).Str("requestId", requestId).Msg("API: Retrieving analysis done")

	requestBody, err := analysisRequestBody(&options)
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
	}

	log.Debug().Str("method", method).Str("requestId", requestId).Float64("progress", response.Progress).Msgf("Status: %s", response.Status)

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

	issues := s.convertSarifResponse(response)
	return issues, status, err
}

func analysisRequestBody(options *AnalysisOptions) ([]byte, error) {
	unknown := "unknown"
	orgName := unknown
	if config.CurrentConfig().GetOrganization() != "" {
		orgName = config.CurrentConfig().GetOrganization()
	}

	request := AnalysisRequest{
		Key: AnalysisRequestKey{
			Type:         "file",
			Hash:         options.bundleHash,
			LimitToFiles: options.limitToFiles,
		},
		Legacy: false,
		AnalysisContext: AnalysisContext{
			Initiatior: "IDE",
			Flow:       "language-server",
			Org: AnalysisContextOrg{
				Name:        orgName,
				DisplayName: unknown,
				PublicId:    unknown,
			},
		},
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

func (s *SnykCodeHTTPClient) convertSarifResponse(response SarifResponse) (issues []snyk.Issue) {
	runs := response.Sarif.Runs
	if len(runs) == 0 {
		return issues
	}
	ruleLink := s.createRuleLink()

	run := runs[0]
	rules := run.Tool.Driver.Rules
	for _, result := range run.Results {
		for _, loc := range result.Locations {
			// convert the documentURI to a path according to our conversion
			path := loc.PhysicalLocation.ArtifactLocation.URI

			myRange := snyk.Range{
				Start: snyk.Position{
					Line:      loc.PhysicalLocation.Region.StartLine - 1,
					Character: loc.PhysicalLocation.Region.StartColumn - 1,
				},
				End: snyk.Position{
					Line:      loc.PhysicalLocation.Region.EndLine - 1,
					Character: loc.PhysicalLocation.Region.EndColumn,
				},
			}

			commands, markdown := s.getCodeFlow(result)
			message := s.getMessage(result)
			rule := s.getRule(rules, result.RuleID)
			formattedMessage := s.getFormattedMessage(message, s.exampleCommitFixesForHover(rule), markdown)
			d := snyk.Issue{
				ID:                  result.RuleID,
				Range:               myRange,
				Severity:            issueSeverity(result.Level),
				Message:             message,
				FormattedMessage:    formattedMessage,
				IssueType:           snyk.CodeSecurityVulnerability,
				AffectedFilePath:    path,
				Product:             snyk.ProductCode,
				IssueDescriptionURL: ruleLink,
				References:          s.getReference(rule),
				Commands:            commands,
			}

			issues = append(issues, d)
		}
	}
	return issues
}

func (s *SnykCodeHTTPClient) getRule(rules []rule, id string) rule {
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	return rule{}
}

func (s *SnykCodeHTTPClient) getMessage(result result) string {
	return fmt.Sprintf("%s (Snyk)", result.Message.Text)
}

func (s *SnykCodeHTTPClient) getReference(r rule) (references []snyk.Reference) {
	for i, exampleFix := range r.Properties.ExampleCommitFixes {
		commitURLString := exampleFix.CommitURL
		commitURL, err := url.Parse(commitURLString)
		if err != nil {
			log.Err(err).
				Str("method", "code.references").
				Str("commitURL", commitURLString).
				Msgf("cannot parse commit url")
			continue
		}
		references = append(references, snyk.Reference{Title: s.getFixDescriptionsForRule(r, i), Url: commitURL})
	}
	return references
}

func (s *SnykCodeHTTPClient) createRuleLink() *url.URL {
	parse, err := url.Parse(codeDescriptionURL)
	if err != nil {
		s.errorReporter.CaptureError(errors2.Wrap(err, "Unable to create Snyk Code rule link"))
	}
	return parse
}

func (s *SnykCodeHTTPClient) getFormattedMessage(message string, commitFixes string, codeFlow string) (msg string) {
	msg = fmt.Sprintf("## Description\n\n%s\n\n---\n", message)
	msg += codeFlow + commitFixes
	return msg
}

func (s *SnykCodeHTTPClient) exampleCommitFixesForHover(rule rule) (msg string) {
	if len(rule.Properties.ExampleCommitFixes) > 0 {
		msg += "\n## Example Commit Fixes: \n\n"
		for i, fix := range rule.Properties.ExampleCommitFixes {
			fixDescription := s.getFixDescriptionsForRule(rule, i)
			if fixDescription != "" {
				msg += fmt.Sprintf("### [%s](%s)", fixDescription, fix.CommitURL)
			}
			msg += "\n```\n"
			for _, line := range fix.Lines {
				lineChangeChar := s.lineChangeChar(line.LineChange)
				msg += fmt.Sprintf("%s %04d : %s\n", lineChangeChar, line.LineNumber, line.Line)
			}
			msg += "```\n\n"
		}
		msg += "---"
	}
	return msg
}

func (s *SnykCodeHTTPClient) getCodeFlow(r result) (commands []snyk.Command, markdown string) {
	flows := r.CodeFlows
	dedupMap := map[string]bool{}
	markdown = "## Snyk Data Flow\n\n"
	for _, cFlow := range flows {
		threadFlows := cFlow.ThreadFlows
		for _, tFlow := range threadFlows {
			for _, tFlowLocation := range tFlow.Locations {
				method := "getCodeFlow"
				physicalLoc := tFlowLocation.Location.PhysicalLocation
				path := physicalLoc.ArtifactLocation.URI
				region := physicalLoc.Region
				myRange :=
					snyk.Range{
						Start: snyk.Position{
							Line:      region.StartLine - 1,
							Character: region.StartColumn - 1,
						},
						End: snyk.Position{
							Line:      region.EndLine - 1,
							Character: region.EndColumn,
						}}

				// IntelliJ does a distinct by start line
				key := fmt.Sprintf("%sL%4d", path, region.StartLine)
				if !dedupMap[key] {
					pos := len(commands)
					command := s.codeFlowToCommand(path, pos, region, myRange)
					commands = append(commands, command)

					markdown += s.codeFlowToMarkdown(path, pos, myRange)
					dedupMap[key] = true
					log.Debug().Str("method", method).Interface("command", command).Send()
					log.Debug().Str("method", method).Interface("markdown", markdown).Send()
				}
			}
		}
	}
	return commands, markdown
}

func (s *SnykCodeHTTPClient) codeFlowToMarkdown(path string, pos int, myRange snyk.Range) string {
	fileName := filepath.Base(path)
	fileURI := uri.PathToUri(path)
	line := myRange.Start.Line + 1 // range is 0-based
	char := myRange.Start.Character
	fileUtil := files.New(s.errorReporter)
	lineOfCode := fileUtil.GetLineOfCode(path, line)
	markdown := fmt.Sprintf(
		"%d. [%s:%d](%s#%d#%d) `%s`\n\n",
		pos,
		fileName,
		line,
		fileURI,
		line,
		char,
		lineOfCode,
	)
	return markdown
}

func (s *SnykCodeHTTPClient) codeFlowToCommand(
	path string,
	index int,
	region region,
	myRange snyk.Range,
) snyk.Command {
	command := snyk.Command{
		Title:     fmt.Sprintf("Snyk Data Flow (%d) %s:%d", index, filepath.Base(path), region.StartLine),
		Command:   snyk.NavigateToRangeCommand,
		Arguments: []interface{}{path, myRange},
	}

	return command
}

func (s *SnykCodeHTTPClient) getFixDescriptionsForRule(rule rule, commitFixIndex int) string {
	fixDescriptions := rule.Properties.ExampleCommitDescriptions
	if len(fixDescriptions) > commitFixIndex {
		return fixDescriptions[commitFixIndex]
	}
	return ""
}

func (s *SnykCodeHTTPClient) lineChangeChar(line string) string {
	switch line {
	case "none":
		return " "
	case "added":
		return "+"
	default:
		return "-"
	}
}

func checkResponseCode(r *http.Response) error {
	if r.StatusCode >= 200 && r.StatusCode <= 299 {
		return nil
	}

	return errors.New("Unexpected response code: " + r.Status)
}
