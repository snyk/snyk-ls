package oss

import "github.com/snyk/snyk-ls/lsp"

type identifiers struct {
	CVE []string `json:"CVE"`
	CWE []string `json:"CWE"`
}

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
	Version        string      `json:"version"`
	PackageManager string      `json:"packageManager"`
	PackageName    string      `json:"packageName"`
	From           []string    `json:"from"`
	Identifiers    identifiers `json:"identifiers"`
	FixedIn        []string    `json:"fixedIn,omitempty"`
}

type ossScanResult struct {
	Vulnerabilities   []ossIssue `json:"vulnerabilities"`
	DisplayTargetFile string     `json:"displayTargetFile"`
}
