package user_behaviour

type commonProperties struct {
	Ide  IDE  `json:"ide"`
	Itly bool `json:"itly"`
}

type AnalysisIsReadyProperties struct {
	AnalysisType AnalysisType `json:"analysisType"`
	Result       Result       `json:"result"`
}

type AnalysisIsTriggeredProperties struct {
	AnalysisType    []AnalysisType `json:"analysisType"`
	TriggeredByUser bool           `json:"triggeredByUser"`
}

type IssueHoverIsDisplayedProperties struct {
	IssueId   string    `json:"issueId"`
	IssueType IssueType `json:"issueType"`
	Severity  Severity  `json:"severity"`
}

type PluginIsUninstalledProperties struct {
}

type PluginIsInstalledProperties struct {
}

type Result string
type AnalysisType string
type IDE string
type Severity string
type IssueType string

const (
	Advisor              AnalysisType = "Snyk Advisor"
	CodeQuality          AnalysisType = "Snyk Code Quality"
	CodeSecurity         AnalysisType = "Snyk Code Security"
	OpenSource           AnalysisType = "Snyk Open Source"
	Container            AnalysisType = "Snyk Container"
	InfrastructureAsCode AnalysisType = "Snyk Infrastructure as Code"
)

const (
	VisualStudioCode IDE = "Visual Studio Code"
	VisualStudio     IDE = "Visual Studio"
	Eclipse          IDE = "Eclipse"
	JetBrains        IDE = "JetBrains"
)

const (
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
	Critical Severity = "Critical"
)

const (
	Success Result = "Success"
	Error   Result = "Error"
)

const (
	AdvisorIssue              IssueType = "Advisor"
	CodeQualityIssue          IssueType = "Code Quality Issue"
	CodeSecurityVulnerability IssueType = "Code Security Vulnerability"
	LicenceIssue              IssueType = "Licence Issue"
	OpenSourceVulnerability   IssueType = "Open Source Vulnerability"
	InfrastructureAsCodeIssue IssueType = "Infrastructure as Code Issue"
	ContainerVulnerability    IssueType = "Container Vulnerability"
)
