//todo remove issues folder and lift up once the snyk domain does not depend on the IDE domain (snyk must return issues not hovers)
package issues

//Issue models a problem, vulnerability, or situation within your code that requires your attention
type Issue struct {
	ID        string
	Severity  Severity
	IssueType Type
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
