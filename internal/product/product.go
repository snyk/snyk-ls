package product

type Product string
type ProductAttributes map[string]interface{}

const (
	ProductOpenSource           Product = "Snyk Open Source"
	ProductCode                 Product = "Snyk Code"
	ProductInfrastructureAsCode Product = "Snyk IaC"
)
