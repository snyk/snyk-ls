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

type SnykAnalysisFailedError struct {
	Msg string
}

func (e SnykAnalysisFailedError) Error() string { return e.Msg }

// AutofixResponse is the json-based structure to which we can translate the results of the HTTP
// request to Autofix upstream.
type AutofixResponse struct {
	Status             string                      `json:"status"`
	AutofixSuggestions []autofixResponseSuggestion `json:"fixes"`
}

type autofixResponseSuggestion = string

type AutofixRequestKey struct {
	Type     string `json:"type"`
	Hash     string `json:"hash"`
	Shard    string `json:"shard"`
	FilePath string `json:"filePath"`
	RuleId   string `json:"ruleId"`
	LineNum  int    `json:"lineNum"` // 1-based
}

type AutofixContextOrg struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName"`
	PublicId    string          `json:"publicId"`
	Flags       map[string]bool `json:"flags"`
}

type AutofixContext struct {
	Initiatior string            `json:"initiatior"`
	Flow       string            `json:"flow,omitempty"`
	Org        AutofixContextOrg `json:"org,omitempty"`
}

type AutofixRequest struct {
	Key            AutofixRequestKey `json:"key"`
	AutofixContext AutofixContext    `json:"autofixContext"`
}

// Should implement `error` interface
type SnykAutofixFailedError struct {
	Msg string
}

func (e SnykAutofixFailedError) Error() string { return e.Msg }
