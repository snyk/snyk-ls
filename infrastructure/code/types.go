/*
 * © 2023 Snyk Limited All rights reserved.
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
	"github.com/snyk/snyk-ls/domain/snyk"
)

type SnykAnalysisFailedError struct {
	Msg string
}

func (e SnykAnalysisFailedError) Error() string { return e.Msg }

type AnalysisRequestKey struct {
	Type         string   `json:"type"`
	Hash         string   `json:"hash"`
	LimitToFiles []string `json:"limitToFiles,omitempty"`
	Shard        string   `json:"shard"`
}

type codeRequestContextOrg struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName"`
	PublicId    string          `json:"publicId"`
	Flags       map[string]bool `json:"flags"`
}

type codeRequestContext struct {
	Initiator string                `json:"initiator"`
	Flow      string                `json:"flow,omitempty"`
	Org       codeRequestContextOrg `json:"org,omitempty"`
}

type AnalysisRequest struct {
	Key             AnalysisRequestKey `json:"key"`
	Severity        int                `json:"severity,omitempty"`
	Prioritized     bool               `json:"prioritized,omitempty"`
	Legacy          bool               `json:"legacy"`
	AnalysisContext codeRequestContext `json:"analysisContext"`
}

// AutofixResponse is the json-based structure to which we can translate the results of the HTTP
// request to Autofix upstream.
type AutofixResponse struct {
	Status             string                     `json:"status"`
	AutofixSuggestions []autofixResponseSingleFix `json:"fixes"`
}

type ExplainResponse struct {
	Status string `json:"status"`
	Explanation string `json:"explanation"`
}

type autofixResponseSingleFix struct {
	Id    string `json:"id"`
	Value string `json:"value"`
}

type AutofixRequestKey struct {
	Type     string `json:"type"`
	Hash     string `json:"hash"`
	Shard    string `json:"shard"`
	FilePath string `json:"filePath"`
	RuleId   string `json:"ruleId"`
	// 1-based to comply with Sarif and Code API, see
	// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html#_Ref493492556
	LineNum int `json:"lineNum"`
}

type ExplainRequestKey struct {
	Type     string `json:"type"`
	Hash     string `json:"hash"`
	Shard    string `json:"shard"`
	FilePath string `json:"filePath"`
	RuleId   string `json:"ruleId"`
	// 1-based to comply with Sarif and Code API, see
	// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html#_Ref493492556
	LineNum int `json:"lineNum"`
}

type AutofixRequest struct {
	Key             AutofixRequestKey  `json:"key"`
	AnalysisContext codeRequestContext `json:"analysisContext"`
}

type ExplainRequest struct {
	Key             ExplainRequestKey  `json:"key"`
	AnalysisContext codeRequestContext `json:"analysisContext"`
}

// Should implement `error` interface
type SnykAutofixFailedError struct {
	Msg string
}

func (e SnykAutofixFailedError) Error() string { return e.Msg }

// AutofixSuggestion models a fix returned by autofix service
type AutofixSuggestion struct {
	FixId       string
	AutofixEdit snyk.WorkspaceEdit
}

type AutofixFeedback struct {
	FixId           string             `json:"fixId"`
	Feedback        string             `json:"feedback"`
	AnalysisContext codeRequestContext `json:"analysisContext"`
}
