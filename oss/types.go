package oss

import "github.com/snyk/snyk-ls/lsp"

type ossIssue struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	LineNumber  int    `json:"lineNumber"`
	Description string `json:"description"`
	References  []struct {
		Title string  `json:"title"`
		Url   lsp.Uri `json:"url"`
	} `json:"references"`
	Version        string   `json:"version"`
	PackageManager string   `json:"packageManager"`
	From           []string `json:"from"`
}

type ossScanResult struct {
	Vulnerabilities   []ossIssue `json:"vulnerabilities"`
	DisplayTargetFile string     `json:"displayTargetFile"`
}
