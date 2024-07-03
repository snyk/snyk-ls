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

package snyk

import (
	"fmt"
	"net/url"
	"time"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

type Reference struct {
	Title string
	Url   *url.URL
}

// Issue models a problem, vulnerability, or situation within your code that requires your attention
type Issue struct {
	// ID uniquely identifies the issue, it is intended to be human-readable
	ID        string
	Severity  Severity
	IssueType Type
	IsIgnored bool // If not explicitly it will default to false so it doesn't break backwards
	// compatibility
	IgnoreDetails *IgnoreDetails // It defaults to nil so it doesn't break backwards compatibility
	// Range identifies the location of this issue in its source of origin (e.g. line & character start & end)
	Range Range
	// Message is a human-readable description of the issue
	Message string
	// todo [jc] this contains a formatted longest message for hovers, this needs to be pushed up and rendered in presentation. [bd] shouldn't the content and formatting be decided by the product?
	FormattedMessage string
	// AffectedFilePath is the file path to the file where the issue was found
	AffectedFilePath string
	// Product is the Snyk product, e.g. Snyk Open Source
	Product product.Product // todo: can we avoid it, if it's part of a scanner interface already?
	// References deliver additional information
	References []Reference
	// IssueDescriptionURL contains a Uri to display more information
	IssueDescriptionURL *url.URL
	// CodeActions can contain workspace edits or commands to be executed
	CodeActions []CodeAction
	// CodelensCommands that can be executed via a codelens
	CodelensCommands []types.CommandData
	// The Ecosystem of the issue, e.g. npm, maven, nuget, etc.
	Ecosystem string
	// A slice of the CWEs of the issue, e.g. CWEs-79
	CWEs []string
	// A slice of the CVEs of the issue
	CVEs []string
	// AdditionalData contains data that can be passed by the product (e.g. for presentation)
	AdditionalData IssueAdditionalData
	// Learn Service Lesson URL
	LessonUrl string `json:"url"`
}

type IssueAdditionalData interface {
	GetKey() string
	GetTitle() string
}

type IgnoreDetails struct {
	Category   string
	Reason     string
	Expiration string
	IgnoredOn  time.Time
	IgnoredBy  string
}

type CodeIssueData struct {
	// Unique key identifying an issue in the whole result set
	Key                string             `json:"key"`
	Title              string             `json:"title"`
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
	IsAutofixable      bool               `json:"isAutofixable"`
	PriorityScore      int                `json:"priorityScore"`
	HasAIFix           bool               `json:"hasAIFix"`
	DataFlow           []DataFlowElement  `json:"dataFlow,omitempty"`
	Details            string             `json:"details"`
}

func (c CodeIssueData) GetKey() string {
	return c.Key
}

func (c CodeIssueData) GetTitle() string {
	return c.Title
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

type OssIssueData struct {
	Key               string         `json:"key"`
	Title             string         `json:"title"`
	Name              string         `json:"name"`
	LineNumber        int            `json:"lineNumber"`
	Identifiers       Identifiers    `jsom:"identifiers"`
	Description       string         `json:"description"`
	References        []Reference    `json:"references,omitempty"`
	Version           string         `json:"version"`
	License           string         `json:"license,omitempty"`
	PackageManager    string         `json:"packageManager"`
	PackageName       string         `json:"packageName"`
	From              []string       `json:"from"`
	FixedIn           []string       `json:"fixedIn,omitempty"`
	UpgradePath       []any          `json:"upgradePath,omitempty"`
	IsUpgradable      bool           `json:"isUpgradable,omitempty"`
	CVSSv3            string         `json:"CVSSv3,omitempty"`
	CvssScore         float64        `json:"cvssScore,omitempty"`
	Exploit           string         `json:"exploit,omitempty"`
	IsPatchable       bool           `json:"isPatchable"`
	ProjectName       string         `json:"projectName"`
	DisplayTargetFile string         `json:"displayTargetFile"`
	Language          string         `json:"language"`
	Details           string         `json:"details"`
	MatchingIssues    []OssIssueData `json:"matchingIssues"`
	Lesson            string         `json:"lesson,omitempty"`
	Remediation       string         `json:"remediation"`
}

type Identifiers struct {
	CWE []string `json:"CWE,omitempty"`
	CVE []string `json:"CVE,omitempty"`
}

func (o OssIssueData) GetKey() string {
	return o.Key
}

func (o OssIssueData) GetTitle() string {
	return o.Title
}

type IaCIssueData struct {
	// Unique key identifying an issue in the whole result set
	Key string `json:"key"`
	// Title: title of the issue
	Title string `json:"title"`
	// PublicID: unique identifier for the issue; it is the same as the ScanIssue.ID
	PublicId string `json:"publicId"`
	// Documentation is a URL which is constructed from the PublicID (e.g. https://security.snyk.io/rules/cloud/SNYK-CC-K8S-13)
	Documentation string `json:"documentation"`
	// LineNumber: line number of the issue in the file
	LineNumber int `json:"lineNumber"`
	// Issue: will contain the issue description
	Issue string `json:"issue"`
	// Impact: will contain the impact description
	Impact string `json:"impact"`
	// Resolve: will contain the resolution description (not to be confused with Remediation)
	Resolve string `json:"resolve"`
	// Path: path to the issue in the file
	Path []string `json:"path"`
	// References: List of reference URLs
	References []string `json:"references,omitempty"`
}

func (i IaCIssueData) GetKey() string {
	return i.Key
}

func (i IaCIssueData) GetTitle() string {
	return i.Title
}

func (i Issue) GetFilterableIssueType() product.FilterableIssueType {
	switch i.Product {
	case product.ProductOpenSource:
		return product.FilterableIssueTypeOpenSource
	case product.ProductInfrastructureAsCode:
		return product.FilterableIssueTypeInfrastructureAsCode
	case product.ProductCode:
		switch i.IssueType {
		case CodeQualityIssue:
			return product.FilterableIssueTypeCodeQuality
		case CodeSecurityVulnerability:
			return product.FilterableIssueTypeCodeSecurity
		default:
			const msg = "Failed to resolve code issue type. Product is Code, but issue type unspecified. Defaulting to Security issue type"
			config.CurrentConfig().Logger().Warn().Int8("IssueType", int8(i.IssueType)).Msg(msg)
			return product.FilterableIssueTypeCodeSecurity
		}
	default:
		return ""
	}
}

func (i Issue) String() string {
	return fmt.Sprintf("%s, ID: %s, Range: %s", i.AffectedFilePath, i.ID, i.Range)
}

type Severity int8

// Type of issue, these will typically match 1o1 to Snyk product lines but are not necessarily coupled to those.
type Type int8

const (
	Critical Severity = iota
	High
	Medium
	Low
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "unknown"
	}
}

const (
	PackageHealth Type = iota
	CodeQualityIssue
	CodeSecurityVulnerability
	LicenceIssue
	DependencyVulnerability
	InfrastructureIssue
	ContainerVulnerability
)
