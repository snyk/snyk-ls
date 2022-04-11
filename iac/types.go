package iac

import "github.com/snyk/snyk-ls/lsp"

type iacScanResult struct {
	TargetFile string `json:"targetFile"`
	IacIssues  []struct {
		PublicID       string  `json:"publicId"`
		Title          string  `json:"title"`
		Severity       string  `json:"severity"`
		LineNumber     int     `json:"lineNumber"`
		Documentation  lsp.Uri `json:"documentation"`
		IacDescription struct {
			Issue   string `json:"issue"`
			Impact  string `json:"impact"`
			Resolve string `json:"resolve"`
		} `json:"iacDescription"`
	} `json:"infrastructureAsCodeIssues"`
}
