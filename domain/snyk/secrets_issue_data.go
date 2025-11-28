package snyk

import (
	"encoding/json"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/snyk-ls/internal/product"
)

type SecretsIssueData struct {
	// Unique key identifying an issue in the whole result set
	Key            string             `json:"key"`
	Title          string             `json:"title"`
	Message        string             `json:"message"`
	Rule           string             `json:"rule"`
	RuleId         string             `json:"ruleId"`
	CWE            []string           `json:"cwe"`
	Markers        []Marker           `json:"markers,omitempty"`
	FilePath       string             `json:"filePath"`
	Regions        []sarif.Region     `json:"regions,omitempty"` // TODO check type for secrets.
	IsSecurityType bool               `json:"isSecurityType"`
	PriorityScore  *int               `json:"priorityScore"`
	MatchingIssues []SecretsIssueData `json:"matchingIssues"` // TODO check need for secrets.
}

func (s SecretsIssueData) GetKey() string {
	return s.Key
}

func (s SecretsIssueData) GetTitle() string {
	return s.Title
}

func (s SecretsIssueData) IsFixable() bool {
	return false
}

func (s SecretsIssueData) GetFilterableIssueType() product.FilterableIssueType {
	return product.FilterableIssueTypeSecrets
}

func (s SecretsIssueData) MarshalJSON() ([]byte, error) {
	type IssueAlias SecretsIssueData
	aliasStruct := struct {
		Type string `json:"type"`
		*IssueAlias
	}{
		Type:       "SecretsIssueData",
		IssueAlias: (*IssueAlias)(&s),
	}
	data, err := json.Marshal(aliasStruct)
	return data, err
}
