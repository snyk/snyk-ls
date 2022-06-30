package snyk

type ProductLine string
type ProductLineAttributes map[string]interface{}

const (
	ProductLineCode                 ProductLine = "Snyk Code"
	ProductLineOpenSource           ProductLine = "Snyk Open Source"
	ProductLineInfrastructureAsCode ProductLine = "Snyk IaC"
)
