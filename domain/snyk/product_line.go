package snyk

import "context"

type ProductLineScanner interface {
	Scan(
		//todo do we need context?
		ctx context.Context,
		path string,
		//todo deliberately calling this garbage because they need to go away - these nonsensical params are here because
		//code and cli based scans have a slightly different modus operandi. We need to unify that and clean this interface
		legacyWorkspacePath string,
		legacyFilesToScan []string,
	) (issues []Issue)

	IsEnabled() bool
	ProductLine() ProductLine
}
type ProductLine string
type ProductLineAttributes map[string]interface{}

const (
	ProductLineCode                 ProductLine = "Snyk Code"
	ProductLineOpenSource           ProductLine = "Snyk Open Source"
	ProductLineInfrastructureAsCode ProductLine = "Snyk IaC"
)
