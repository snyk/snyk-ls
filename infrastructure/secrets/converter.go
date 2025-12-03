/*
 * © 2024 Snyk Limited
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

package secrets

import (
	"context"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	pkgWorkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/types"
)

// ProcessScanResults takes the results from the scanner and transforms them into
// our internal issue format. It also populates the given package cache with the
// found problems per package.
//   - scanOutput: the output of the scan (can be either a []byte or []workflow.Data)
func ProcessScanResults(
	ctx context.Context,
	scanOutput any,
) ([]types.Issue, error) {
	if ctx.Err() != nil {
		return nil, nil
	}

	// new ostest workflow result processing
	if output, ok := scanOutput.([]pkgWorkflow.Data); ok {
		return processSecretsTestWorkFlowData(ctx, output)
	}

	return nil, nil
}

func processSecretsTestWorkFlowData(
	ctx context.Context,
	scanOutput []pkgWorkflow.Data,
) ([]types.Issue, error) {
	var issues []types.Issue
	var err error
	for _, data := range scanOutput {
		testResults := ufm.GetTestResultsFromWorkflowData(data)
		for _, testResult := range testResults {
			issues, err = convertTestResultToIssues(ctx, testResult)
			if err != nil {
				return nil, fmt.Errorf("couldn't convert test result to Secrets issues: %w", err)
			}
		}
	}
	return issues, nil
}
