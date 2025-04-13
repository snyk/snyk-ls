/*
 * © 2025 Snyk Limited
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

package types

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/internal/product"
)

type Severity int8

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

// Type of issue, these will typically match 1o1 to Snyk product lines but are not necessarily coupled to those.
type IssueType int8

const (
	PackageHealth IssueType = iota
	CodeQualityIssue
	CodeSecurityVulnerability
	LicenseIssue
	DependencyVulnerability
	InfrastructureIssue
	ContainerVulnerability
)

type CodeAction interface {
	Groupable
	GetTitle() string
	GetIsPreferred() *bool
	GetEdit() *WorkspaceEdit
	GetDeferredEdit() *func() *WorkspaceEdit
	GetCommand() *CommandData
	GetDeferredCommand() *func() *CommandData
	GetUuid() *uuid.UUID
	SetTitle(title string)
	SetEdit(edit *WorkspaceEdit)
}

type Reference struct {
	Title string
	Url   *url.URL
}

type Issue interface {
	fmt.Stringer
	GetID() string
	GetRange() Range
	GetMessage() string
	GetFormattedMessage() string
	GetAffectedFilePath() FilePath
	GetContentRoot() FilePath
	GetIsNew() bool
	GetIsIgnored() bool
	SetIsIgnored(isIgnored bool)
	GetSeverity() Severity
	GetIgnoreDetails() *IgnoreDetails
	GetProduct() product.Product
	GetFingerprint() string
	GetGlobalIdentity() string
	GetAdditionalData() IssueAdditionalData
	GetEcosystem() string
	GetCWEs() []string
	GetCVEs() []string
	GetIssueType() IssueType
	GetLessonUrl() string
	GetIssueDescriptionURL() *url.URL
	GetCodeActions() []CodeAction
	GetCodelensCommands() []CommandData
	GetFilterableIssueType() product.FilterableIssueType
	GetRuleID() string
	GetReferences() []Reference
	GetFindingsId() string
	SetCodelensCommands(lenses []CommandData)
	SetLessonUrl(url string)
	SetAdditionalData(data IssueAdditionalData)
	SetGlobalIdentity(globalIdentity string)
	SetIsNew(isNew bool)
	SetCodeActions(actions []CodeAction)
	SetRange(r Range)
	SetIgnoreDetails(ignoreDetails *IgnoreDetails)
}

type IssueAdditionalData interface {
	json.Marshaler
	GetKey() string
	GetTitle() string
	IsFixable() bool
	GetFilterableIssueType() product.FilterableIssueType
}

type SeverityIssueCounts map[Severity]IssueCount
type IssueCount struct {
	Total   int
	Open    int
	Ignored int
}

func (s ScanData) GetSeverityIssueCounts() SeverityIssueCounts {
	sic := make(SeverityIssueCounts)

	for _, issue := range s.Issues {
		UpdateSeverityCount(sic, issue)
	}

	return sic
}

func UpdateSeverityCount(sic SeverityIssueCounts, issue Issue) {
	ic, exists := sic[issue.GetSeverity()]
	if !exists {
		ic = IssueCount{}
	}
	if issue.GetIsIgnored() {
		ic.Ignored++
	} else {
		ic.Open++
	}
	ic.Total++

	sic[issue.GetSeverity()] = ic
}

type FilePath string

type IssuesByFile map[FilePath][]Issue
