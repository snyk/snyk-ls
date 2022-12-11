package product

type Product string
type ProductAttributes map[string]interface{}
type FilterableIssueType string

const (
	ProductOpenSource           Product = "Snyk Open Source"
	ProductCode                 Product = "Snyk Code"
	ProductInfrastructureAsCode Product = "Snyk IaC"
)

const (
	OpenSource           FilterableIssueType = "Open Source"
	CodeQuality          FilterableIssueType = "Code Quality"
	CodeSecurity         FilterableIssueType = "Code Security"
	InfrastructureAsCode FilterableIssueType = "Infrastructure As Code"
)
