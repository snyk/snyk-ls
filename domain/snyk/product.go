package snyk

import "context"

type ProductScanner interface {
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
	Product() Product
	SupportedCommands() []CommandName
}
type Product string
type ProductAttributes map[string]interface{}

const (
	ProductCode                 Product = "Snyk Code"
	ProductOpenSource           Product = "Snyk Open Source"
	ProductInfrastructureAsCode Product = "Snyk IaC"
)
