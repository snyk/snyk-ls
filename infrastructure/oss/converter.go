/*
 * © 2024-2025 Snyk Limited
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

// Package oss implements the OSS scanner
package oss

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// ConvertJSONToIssues converts OSS JSON output to Issue objects with optional learn service
// This is a standalone version of CLIScanner.unmarshallAndRetrieveAnalysis
func ConvertJSONToIssues(engine workflow.Engine, logger *zerolog.Logger, jsonData []byte, learnService learn.Service, workDir string, configResolver types.ConfigResolverInterface) ([]types.Issue, error) {
	ctx := ctx2.NewContextWithEngine(context.Background(), engine)
	ctx = ctx2.NewContextWithConfigResolver(ctx, configResolver)
	issues, err := ProcessScanResults(ctx, jsonData, error_reporting.NewTestErrorReporter(engine), learnService, make(map[string][]types.Issue), false, config.FormatMd)
	return issues, err
}

// ProcessScanResults takes the results from the scanner and transforms them into
// our internal issue format. It also populates the given package cache with the
// found problems per package.
//   - scanOutput: the output of the scan (can be either a []byte or []workflow.Data)
func ProcessScanResults(ctx context.Context, scanOutput any, errorReporter error_reporting.ErrorReporter, learnService learn.Service, packageIssueCache map[string][]types.Issue, readFiles bool, format string) ([]types.Issue, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	logger := ctx2.LoggerFromContext(ctx).With().Str("method", "ProcessScanResults").Logger()
	deps, found := ctx2.DependenciesFromContext(ctx)
	var engine workflow.Engine
	if found {
		if e, ok := deps[ctx2.DepEngine].(workflow.Engine); ok {
			engine = e
		}
	}
	if engine == nil {
		logger.Error().Msg("engine not found in context dependencies, results may be incomplete")
		return nil, fmt.Errorf("engine not found in context dependencies for ProcessScanResults")
	}
	configResolver, _ := ctx2.ConfigResolverFromContext(ctx)
	workDir := ctx2.WorkDirFromContext(ctx)
	filePath := ctx2.FilePathFromContext(ctx)
	folderConfig, _ := ctx2.FolderConfigFromContext(ctx)

	// new ostest workflow result processing
	if output, ok := scanOutput.([]workflow.Data); ok {
		return processOsTestWorkFlowData(ctx, output, packageIssueCache)
	}

	// unchanged legacy workflow
	var allIssues []types.Issue
	scanOutputBytes, ok := scanOutput.([]byte)
	if !ok || len(scanOutputBytes) == 0 {
		return nil, nil
	}

	streamErr := StreamOssJson(bytes.NewReader(scanOutputBytes), func(sr *scanResult) error {
		targetFilePath := getAbsTargetFilePath(&logger, sr.Path, sr.DisplayTargetFile, workDir, filePath)

		fileContent := getFileContent(targetFilePath, readFiles, logger)

		issues := convertScanResultToIssues(engine, configResolver, sr, workDir, targetFilePath, fileContent, learnService, errorReporter, packageIssueCache, format, folderConfig)
		allIssues = append(allIssues, issues...)
		return nil
	})
	if streamErr != nil {
		errorReporter.CaptureErrorAndReportAsIssue(filePath, streamErr)
		return nil, nil
	}

	return allIssues, nil
}

func getFileContent(targetFilePath types.FilePath, readFiles bool, logger zerolog.Logger) []byte {
	if targetFilePath != "" && readFiles && uri.IsRegularFile(targetFilePath) {
		fc, err := os.ReadFile(string(targetFilePath))
		if err != nil {
			logger.Error().Err(err).Str("filePath", string(targetFilePath)).Msg("Failed to read file")
		}
		return fc
	}
	return []byte{}
}

// StreamOssJson decodes the OSS CLI JSON from r, invoking yield once per scanResult.
//
// The array form ([{...}, {...}]) is consumed element-by-element via json.Decoder so
// that only one *scanResult is resident at a time (IDE-1940). The single-object form
// ({...}) is supported for parity with UnmarshallOssJson: yield is invoked once.
//
// Contract: yield MUST NOT retain *sr across calls. StreamOssJson may reuse the
// underlying scanResult pointer between iterations; any fields the caller needs
// after yield returns must be copied out by the caller.
//
// Returns the first error encountered (from r, from the decoder, or from yield).
func StreamOssJson(r io.Reader, yield func(sr *scanResult) error) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return errors.Join(err, fmt.Errorf("couldn't read OSS CLI response opening token"))
	}
	delim, _ := tok.(json.Delim)
	switch delim {
	case '[':
		for dec.More() {
			sr := &scanResult{}
			if decErr := dec.Decode(sr); decErr != nil {
				return errors.Join(decErr, fmt.Errorf("couldn't decode OSS CLI scanResult element"))
			}
			if yieldErr := yield(sr); yieldErr != nil {
				return yieldErr
			}
		}
		// Consume closing ']' so the stream is fully drained; ignore error after the loop.
		_, _ = dec.Token()
		return nil
	case '{':
		// We've already consumed the opening '{'. Rebuild the full body by prepending
		// it to dec.Buffered() (bytes read but not yet consumed) and any remaining
		// bytes from r, then unmarshal as a single scanResult. Single-object mode is
		// not the hot path, so correctness trumps streaming here.
		var buf bytes.Buffer
		buf.WriteByte('{')
		if _, copyErr := io.Copy(&buf, io.MultiReader(dec.Buffered(), r)); copyErr != nil {
			return errors.Join(copyErr, fmt.Errorf("couldn't read single-object OSS CLI response"))
		}
		sr := &scanResult{}
		if unmErr := json.Unmarshal(buf.Bytes(), sr); unmErr != nil {
			return errors.Join(unmErr, fmt.Errorf("couldn't unmarshal single-object OSS CLI response"))
		}
		return yield(sr)
	default:
		return fmt.Errorf("unexpected OSS CLI response opening token: %v", tok)
	}
}

// UnmarshallOssJson is a standalone version of CLIScanner.unmarshallOssJson
func UnmarshallOssJson(res []byte) (scanResults []scanResult, err error) {
	output := string(res)
	if strings.HasPrefix(output, "[") {
		err = json.Unmarshal(res, &scanResults)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
	} else {
		var result scanResult
		err = json.Unmarshal(res, &result)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
		scanResults = append(scanResults, result)
	}
	return scanResults, err
}
