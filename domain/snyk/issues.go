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
	//todo this contains a formatted longest message for hovers, this needs to be pushed up and rendered in presentation
	LegacyMessage string
	// AffectedFilePath is the file path to the file where the issue was found
	AffectedFilePath string
	Product          Product
	References       []*url.URL
	// IssueDescriptionURL contains a Uri to display more information
	IssueDescriptionURL *url.URL
}

func (i Issue) String() string {
	return fmt.Sprintf("%s, ID: %s, Range: %s", i.AffectedFilePath, i.ID, i.Range)
}

type Position struct {
	/**
	 * Line position in a document (zero-based).
	 */
	Line int
	/**
	 * Character offset on a line in a document (zero-based).
	 */
	Character int
}

func (p Position) String() string {
	return fmt.Sprintf("%d:%d", p.Line, p.Character)
}

type Range struct {
	/**
	 * The range's start position.
	 */
	Start Position

	/**
	 * The range's end position.
	 */
	End Position
}

func (r Range) String() string {
	return fmt.Sprintf("%s-%s", r.Start, r.End)
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
