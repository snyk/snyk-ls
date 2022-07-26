package snyk

import (
	"fmt"
	"net/url"
)

//Issue models a problem, vulnerability, or situation within your code that requires your attention
type Issue struct {
	//ID uniquely identifies the issue, it is intended to be human-readable
	ID        string
	Severity  Severity
	IssueType Type
	// Range identifies the location of this issue in its source of origin (e.g. line & character start & end)
	Range Range
	// Message is a human-readable description of the issue
	Message string
	// todo [jc] this contains a formatted longest message for hovers, this needs to be pushed up and rendered in presentation. [bd] shouldn't the content and formatting be decided by the product?
	FormattedMessage string
	// AffectedFilePath is the file path to the file where the issue was found
	AffectedFilePath string
	// Product is the Snyk product, e.g. Snyk Open Source
	Product Product
	// References deliver additional information
	References []*url.URL
	// IssueDescriptionURL contains a Uri to display more information
	IssueDescriptionURL *url.URL
	// CodeActions can contain workspace edits or commands to be executed
	CodeActions []CodeAction
	// Commands that can be executed
	Commands []Command
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

const (
	PackageHealth Type = iota
	CodeQualityIssue
	CodeSecurityVulnerability
	LicenceIssue
	DependencyVulnerability
	InfrastructureIssue
	ContainerVulnerability
)
