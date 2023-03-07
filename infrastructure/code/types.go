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

type CodeIssueData struct {
	Message            string             `json:"message"`
	Rule               string             `json:"rule"`
	RuleId             string             `json:"ruleId"`
	RepoDatasetSize    int                `json:"repoDatasetSize"`
	ExampleCommitFixes []ExampleCommitFix `json:"exampleCommitFixes"`
	CWE                []string           `json:"cwe"`
	Text               string             `json:"text"`
	Markers            []Marker           `json:"markers,omitempty"`
	Cols               CodePoint          `json:"cols"`
	Rows               CodePoint          `json:"rows"`
	IsSecurityType     bool               `json:"isSecurityType"`
}

type ExampleCommitFix struct {
	CommitURL string             `json:"commitURL"`
	Lines     []CommitChangeLine `json:"lines"`
}

type CommitChangeLine struct {
	Line       string `json:"line"`
	LineNumber int    `json:"lineNumber"`
	LineChange string `json:"lineChange"`
}

type CodePoint = [2]int

type Marker struct {
	Msg CodePoint        `json:"msg"`
	Pos []MarkerPosition `json:"pos"`
}

type MarkerPosition struct {
	Cols CodePoint `json:"cols"`
	Rows CodePoint `json:"rows"`
	File string    `json:"file"`
}
