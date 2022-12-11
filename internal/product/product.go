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
	FilterableIssueTypeOpenSource           FilterableIssueType = "Open Source"
	FilterableIssueTypeCodeQuality          FilterableIssueType = "Code Quality"
	FilterableIssueTypeCodeSecurity         FilterableIssueType = "Code Security"
	FilterableIssueTypeInfrastructureAsCode FilterableIssueType = "Infrastructure As Code"
)
