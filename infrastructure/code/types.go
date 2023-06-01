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

// AutofixResponse is the json-based structure to which we can translate the results of the HTTP
// request to Autofix upstream.
type AutofixResponse struct {
	Status             string                     `json:"status"`
	AutofixSuggestions []autofixResponseSingleFix `json:"fixes"`
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

type AutofixRequest struct {
	Key            AutofixRequestKey  `json:"key"`
	AutofixContext codeRequestContext `json:"autofixContext"`
}

// Should implement `error` interface
type SnykAutofixFailedError struct {
	Msg string
}

func (e SnykAutofixFailedError) Error() string { return e.Msg }

// AutofixSuggestion models a fix returned by autofix service
type AutofixSuggestion struct {
	// CodeAction can contain workspace edits or commands to be executed.
	// TODO(alex.gronskiy): currently we return full file fixed code and edits contain thus "full
	// file replace".
	// This is a known point of improvement which is easy to implement but will be
	// done later on re-iteration.
	AutofixEdit snyk.WorkspaceEdit
}
