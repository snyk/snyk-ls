package iac

import (
	"github.com/snyk/snyk-ls/presentation/lsp"
)

type iacScanResult struct {
	TargetFile string     `json:"targetFile"`
	IacIssues  []iacIssue `json:"infrastructureAsCodeIssues"`
}

type iacDescription struct {
	Issue   string `json:"issue"`
	Impact  string `json:"impact"`
	Resolve string `json:"resolve"`
}

type iacIssue struct {
	PublicID       string         `json:"publicId"`
	Title          string         `json:"title"`
	Severity       string         `json:"severity"`
	LineNumber     int            `json:"lineNumber"`
	Documentation  lsp.Uri        `json:"documentation"`
	IacDescription iacDescription `json:"iacDescription"`
}
