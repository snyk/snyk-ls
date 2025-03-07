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
	"encoding/json"
	"fmt"
	"net/url"
	"sync"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/delta"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

var (
	_ delta.Fingerprintable = (*Issue)(nil)
	_ delta.Identifiable    = (*Issue)(nil)
	_ delta.Locatable       = (*Issue)(nil)
	_ delta.Pathable        = (*Issue)(nil)
	_ types.Issue           = (*Issue)(nil)
)

// Issue models a problem, vulnerability, or situation within your code that requires your attention
type Issue struct {
	// ID uniquely identifies the issue, it is intended to be human-readable. It's also rule id
	ID        string
	Severity  types.Severity
	IssueType types.IssueType
	IsIgnored bool // If not explicitly it will default to false, so it doesn't break backwards
	IsNew     bool
	// compatibility
	IgnoreDetails *types.IgnoreDetails // It defaults to nil, so it doesn't break backwards compatibility
	// Range identifies the location of this issue in its source of origin (e.g. line & character start & end)
	Range types.Range
	// Message is a human-readable description of the issue
	Message string
	// todo [jc] this contains a formatted longest message for hovers, this needs to be pushed up and rendered in presentation. [bd] shouldn't the content and formatting be decided by the product?
	FormattedMessage string
	// AffectedFilePath is the file path to the file where the issue was found
	AffectedFilePath types.FilePath
	// Product is the Snyk product, e.g. Snyk Open Source
	Product product.Product // todo: can we avoid it, if it's part of a scanner interface already?
	// References deliver additional information
	References []types.Reference
	// IssueDescriptionURL contains a Uri to display more information
	IssueDescriptionURL *url.URL
	// CodeActions can contain workspace edits or commands to be executed
	CodeActions []types.CodeAction `json:"-"` // don't marshall/unmarshall as this is an interface and we don't need it
	// CodelensCommands that can be executed via a codelens
	CodelensCommands []types.CommandData
	// The Ecosystem of the issue, e.g. npm, maven, nuget, etc.
	Ecosystem string
	// A slice of the CWEs of the issue, e.g. CWEs-79
	CWEs []string
	// A slice of the CVEs of the issue
	CVEs []string
	// AdditionalData contains data that can be passed by the product (e.g. for presentation)
	AdditionalData types.IssueAdditionalData `json:"additionalData"`
	// Learn Service Lesson URL
	LessonUrl      string `json:"url"`
	Fingerprint    string
	GlobalIdentity string
	m              sync.RWMutex
}

func (i *Issue) Clone() *Issue {
	i.m.RLock()
	defer i.m.RUnlock()
	return &Issue{
		ID:                  i.ID,
		Severity:            i.Severity,
		IssueType:           i.IssueType,
		IsIgnored:           i.IsIgnored,
		IsNew:               i.IsNew,
		IgnoreDetails:       i.IgnoreDetails,
		Range:               i.Range,
		Message:             i.Message,
		FormattedMessage:    i.FormattedMessage,
		AffectedFilePath:    i.AffectedFilePath,
		Product:             i.Product,
		References:          i.References,
		IssueDescriptionURL: i.IssueDescriptionURL,
		CodeActions:         i.CodeActions,
		CodelensCommands:    i.CodelensCommands,
		Ecosystem:           i.Ecosystem,
		CWEs:                i.CWEs,
		CVEs:                i.CVEs,
		AdditionalData:      i.AdditionalData,
		LessonUrl:           i.LessonUrl,
		Fingerprint:         i.Fingerprint,
		GlobalIdentity:      i.GlobalIdentity,
		m:                   sync.RWMutex{},
	}
}

func (i *Issue) SetRange(r types.Range) {
	i.m.Lock()
	defer i.m.Unlock()
	i.Range = r
}

func (i *Issue) GetReferences() []types.Reference {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.References
}

func (i *Issue) SetCodeActions(actions []types.CodeAction) {
	i.m.Lock()
	defer i.m.Unlock()

	i.CodeActions = actions
}

func (i *Issue) SetCodelensCommands(lenses []types.CommandData) {
	i.m.Lock()
	defer i.m.Unlock()

	i.CodelensCommands = lenses
}

func (i *Issue) GetCodelensCommands() []types.CommandData {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.CodelensCommands
}

func (i *Issue) GetCodeActions() []types.CodeAction {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.CodeActions
}

func (i *Issue) GetIssueDescriptionURL() *url.URL {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.IssueDescriptionURL
}

func (i *Issue) GetEcosystem() string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Ecosystem
}

func (i *Issue) GetCWEs() []string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.CWEs
}

func (i *Issue) GetCVEs() []string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.CVEs
}

func (i *Issue) GetIssueType() types.IssueType {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.IssueType
}

func (i *Issue) GetLessonUrl() string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.LessonUrl
}

func (i *Issue) GetID() string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.ID
}

func (i *Issue) GetDescription() string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Message
}

func (i *Issue) GetRange() types.Range {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Range
}

func (i *Issue) GetMessage() string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Message
}

func (i *Issue) GetFormattedMessage() string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.FormattedMessage
}

func (i *Issue) GetAffectedFilePath() types.FilePath {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.AffectedFilePath
}

func (i *Issue) GetIsIgnored() bool {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.IsIgnored
}

func (i *Issue) GetSeverity() types.Severity {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Severity
}

func (i *Issue) GetIgnoreDetails() *types.IgnoreDetails {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.IgnoreDetails
}

func (i *Issue) GetProduct() product.Product {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Product
}

func (i *Issue) GetAdditionalData() types.IssueAdditionalData {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.AdditionalData
}

func (i *Issue) SetLessonUrl(url string) {
	i.m.Lock()
	defer i.m.Unlock()
	i.LessonUrl = url
}

func (i *Issue) SetAdditionalData(data types.IssueAdditionalData) {
	i.m.Lock()
	defer i.m.Unlock()
	i.AdditionalData = data
}

func (i *Issue) StartLine() int {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Range.Start.Line
}

func (i *Issue) EndLine() int {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Range.End.Line
}

func (i *Issue) StartColumn() int {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Range.Start.Character
}

func (i *Issue) EndColumn() int {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Range.End.Character
}

func (i *Issue) GetIsNew() bool {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.IsNew
}

func (i *Issue) SetIsNew(isNew bool) {
	i.m.Lock()
	defer i.m.Unlock()
	i.IsNew = isNew
}

func (i *Issue) GetGlobalIdentity() string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.GlobalIdentity
}

func (i *Issue) SetGlobalIdentity(id string) {
	i.m.Lock()
	defer i.m.Unlock()

	i.GlobalIdentity = id
}

func (i *Issue) GetPath() types.FilePath {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.AffectedFilePath
}

func (i *Issue) GetFingerprint() string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.Fingerprint
}

func (i *Issue) SetFingerPrint(fingerprint string) {
	i.m.Lock()
	defer i.m.Unlock()

	i.Fingerprint = fingerprint
	i.GlobalIdentity = util.HashWithoutConversion([]byte(fingerprint))
}

func (i *Issue) GetRuleID() string {
	i.m.RLock()
	defer i.m.RUnlock()
	return i.ID
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

type SeverityChange struct {
	OriginalSeverity string `json:"originalSeverity"`
	NewSeverity      string `json:"newSeverity"`
	Reason           string `json:"reason"`
}

type AppliedPolicyRules struct {
	Annotation     Annotation     `json:"annotation,omitempty"`
	SeverityChange SeverityChange `json:"severityChange,omitempty"`
}

type Annotation struct {
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Identifiers struct {
	CWE []string `json:"CWE,omitempty"`
	CVE []string `json:"CVE,omitempty"`
}

func (i *Issue) GetFilterableIssueType() product.FilterableIssueType {
	switch i.Product {
	case product.ProductOpenSource:
		return product.FilterableIssueTypeOpenSource
	case product.ProductInfrastructureAsCode:
		return product.FilterableIssueTypeInfrastructureAsCode
	case product.ProductCode:
		switch i.IssueType {
		case types.CodeQualityIssue:
			return product.FilterableIssueTypeCodeQuality
		case types.CodeSecurityVulnerability:
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

func (i *Issue) String() string {
	return fmt.Sprintf("%s, ID: %s, Range: %s", i.GetAffectedFilePath(), i.GetID(), i.GetRange())
}

type Severity int8

func (i *Issue) UnmarshalJSON(data []byte) error {
	type IssueAlias Issue
	temp := &struct {
		AdditionalData json.RawMessage `json:"additionalData"`
		*IssueAlias
	}{
		IssueAlias: (*IssueAlias)(i),
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	var additionalType struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(temp.AdditionalData, &additionalType); err != nil {
		return err
	}

	switch additionalType.Type {
	case "CodeIssueData":
		var codeData CodeIssueData
		if err := json.Unmarshal(temp.AdditionalData, &codeData); err != nil {
			return err
		}
		i.AdditionalData = codeData
	case "IaCIssueData":
		var iacData IaCIssueData
		if err := json.Unmarshal(temp.AdditionalData, &iacData); err != nil {
			return err
		}
		i.AdditionalData = iacData
	case "OssIssueData":
		var ossData OssIssueData
		if err := json.Unmarshal(temp.AdditionalData, &ossData); err != nil {
			return err
		}
		i.AdditionalData = ossData
	case "":
		return nil
	default:
		return fmt.Errorf("unknown additional data type: %s", additionalType.Type)
	}
	return nil
}

func (i *Issue) SetID(id string) {
	i.m.Lock()
	defer i.m.Unlock()

	i.ID = id
}
